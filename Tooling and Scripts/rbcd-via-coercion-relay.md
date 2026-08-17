# RBCD-via-Coercion: Self-Writing Resource-Based Constrained Delegation

A way to write Resource-Based Constrained Delegation (RBCD) rights onto a
target computer object **without any pre-existing ACL edge onto it at
all** — distinct from the classic RBCD abuse chain (`GenericWrite`/
`WriteDacl` already held on the target by an attacker-controlled principal,
see [[windows-active-directory-attack-surface-checklist]] §4 and Elad
Shamir's ["Wagging the
Dog"](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html), the paper
that first described the RBCD-as-computer-takeover primitive).

## The precondition being abused

Any domain-joined computer object has a default `SELF` ACE granting it
write access to its own `msDS-AllowedToActOnBehalfOfOtherIdentity`
attribute — this is intentional AD design since Server 2012 R2, letting a
machine's own local administrator configure RBCD onto itself without
needing Domain Admin rights. Nobody has to have granted an attacker
anything on the target for this write right to exist; it's already there,
on every computer object, by default.

## The attack

1. **Coerce the target computer to authenticate** to an attacker-controlled
   listener over SMB — PetitPotam (`EfsRpcAddUsersToFile`, MS-EFSRPC) and
   PrinterBug (`RpcRemoteFindFirstPrinterChangeNotificationEx`, MS-RPRN) are
   the standard primitives; `netexec`'s `coerce_plus` module fires either.
2. **Relay that authentication to LDAP(S) on a domain controller**, not back
   to the target itself — because the machine account authenticating *is*
   the target, the SELF write right described above applies, and the relay
   session can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the
   target's own computer object using its own captured authentication.
   `impacket-ntlmrelayx -t ldaps://<dc> --delegate-access
   --escalate-user '<attacker-controlled-account>$'` does the write and
   grants that account RBCD rights on the coerced target in one step.
3. Once written, standard S4U2Self + S4U2Proxy
   (`impacket-getST -spn <service>/<target> -impersonate <victim>
   '<domain>/<attacker-controlled-account>$:<password>'`) impersonates any
   domain user (typically Administrator) against the target's services.

## Preconditions that gate whether this actually works

- **Target's SMB *server* must not enforce signing** (`signing:False`) —
  this is what makes the coerced authentication relayable at the SMB layer
  in the first place. Domain controllers enforce this by default; member
  servers frequently don't.
- **Target's SMB *client* (the outbound coercion callback) enforcing
  signing is a separate, independent blocker** from the server-side
  setting above, and breaks a plain relay with `The client requested
  signing. Relaying to LDAP will not work!` even when the server side is
  fine. The bypass is `--remove-mic` (CVE-2019-1040, "[Drop the
  MIC](https://securityboulevard.com/2019/06/drop-the-mic-cve-2019-1040/)")
  — strips the NTLM Message Integrity Code and the
  `NTLMSSP_NEGOTIATE_(ALWAYS_)SIGN` flags from the relayed message before
  it reaches the LDAP server. **Test this per machine, not per patch
  baseline** — two hosts on the identical OS build can differ in real-world
  exposure to this bypass, most likely because the underlying mitigation is
  GPO/registry-configurable rather than a pure binary patch (observed
  directly on [[Pirate#Foothold|Pirate]]: DC01 and WEB01 share the exact
  same build number, but `--remove-mic` is blocked on DC01 and succeeds
  cleanly on WEB01).
- **You need a credential (or an existing computer account) to be the
  `--escalate-user`** — RBCD is written *for* a specific attacker-controlled
  principal, so this chain still needs some starting foothold capable of
  triggering the coercion and holding a delegating identity, it's just not
  gated on any pre-existing ACL against the target.

## A NAT/relay-delay trap worth knowing before concluding "no route"

If the coercion callback has to traverse a NAT hop (e.g. a dual-homed pivot
box translating the target's outbound connection, as with Hyper-V's default
switch), the connection can take 100+ seconds to actually land at the
relay listener — a short capture window (a `tcpdump` run for 5-20 seconds)
will show nothing and looks exactly like "the coercion callback never
reaches the attacker," even though it eventually does. Confirm classic IP
forwarding is genuinely off (`HKLM:\SYSTEM\...\Tcpip\Parameters\
IPEnableRouter`, should read `0` for NAT rather than real routing) before
trusting a short negative window, and re-test with a multi-minute capture
before concluding the target is unreachable.

## Seen on

- [[Pirate#Foothold|Pirate]] — coerced WEB01 (SMB signing disabled) via
  PetitPotam/PrinterBug, relayed with `--remove-mic` to
  `ldaps://DC01`, writing RBCD rights for a controlled machine account
  (`MS01$`, itself obtained via [[pre2k-default-computer-account-passwords]])
  onto WEB01's own computer object — no pre-existing ACL edge onto WEB01
  existed anywhere in the domain. S4U2Proxy as `MS01$` impersonating
  Administrator against `cifs/WEB01.pirate.htb` led straight to a
  `secretsdump` of WEB01, recovering the local Administrator hash and
  user.txt. The identical direct-coercion-to-LDAP-relay attempt against
  DC01 itself (§4 of the box's foothold notes) failed — DC01 enforces SMB
  client-side signing on its own coercion callback *and* is hardened
  against the `--remove-mic` bypass, which is exactly the per-machine
  difference this note flags above.
