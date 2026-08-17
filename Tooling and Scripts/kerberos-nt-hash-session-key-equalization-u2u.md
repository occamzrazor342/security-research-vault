# Kerberos NT-Hash/Session-Key Equalization for S4U2Self+U2U

A technique for making a Kerberos User-to-User (U2U) exchange decrypt with a
session key you already know, by overwriting an account's *NT hash*
(long-term key) to be byte-identical to a *session key* from a TGT you
already hold for that same account — without ever learning or needing the
account's own real password.

## Why this is needed

S4U2Self normally lets a service impersonate an arbitrary user to itself, but
the resulting "evidence" ticket is encrypted with the service account's own
long-term key by default. U2U changes that: it asks the KDC to encrypt the
S4U2Self reply with the *session key of an existing TGT* instead of the
service's long-term key. Downstream S4U2Proxy (impersonating a target user
against a real service, e.g. `cifs/dc.<domain>`) then relies on being able to
decrypt that U2U ticket correctly.

If you don't independently possess the account's real password/NT hash but
you *do* already hold a valid TGT for it (e.g. via an unrelated password
reset you performed, where you know the reset password), you can still reach
this: derive that TGT's session key, then overwrite the account's real NT
hash to equal that session key value. From that point, the identical ccache
(never re-requested — a fresh TGT request would generate a different session
key) decrypts correctly against both the account's own long-term key *and*
the U2U mechanism, because they're now the same bytes.

## The steps

1. **Obtain a TGT for the target account** via any password you set for it
   (e.g. after resetting its password through some other privilege):

```bash
python3 -c "
import hashlib
h = hashlib.new('md4', 'YourResetPassword!'.encode('utf-16le')).hexdigest()
print('NT hash:', h)
"
impacket-getTGT 'domain/TargetAccount$' -hashes ':<nt-hash-of-reset-password>' -dc-ip <dc>
```

2. **Extract that TGT's session key** from the resulting ccache — **don't
   discard or re-request the ticket after this point**, the session key you
   extract must match the ticket you keep using:

```python
from impacket.krb5.ccache import CCache
cc = CCache.loadFile('TargetAccount$.ccache')
for c in cc.credentials:
    print('Session Key:', c['key']['keyvalue'].hex())
```

3. **Overwrite the account's NT hash to equal that session key**, using a
   direct hash-set primitive — **not** a normal password-reset call. A
   normal `bloodyAD set password`/`Set-ADAccountPassword` derives and syncs
   *all* key material for the account (NT hash, all AES key types) from a
   plaintext password you supply, which won't produce this specific NT-hash
   value and will also invalidate the reasoning below. `impacket-changepasswd`
   with `-newhashes` sets the NT hash directly:

```bash
impacket-changepasswd 'domain/TargetAccount$@dc.domain' \
    -newhashes ':<session-key-hex>' \
    -hashes ':<nt-hash-of-reset-password>' \
    -dc-ip <dc> -k
```

4. **Reuse the exact same (pre-change) ccache** for the S4U2Self+U2U →
   S4U2Proxy request. The KDC's own decryption of the U2U-encrypted evidence
   ticket now succeeds because the account's long-term key genuinely equals
   the session key baked into that specific ticket:

```bash
python3 getST.py -spn '<target-service>/<target-host>' \
    -impersonate <victim-to-impersonate> -dc-ip <dc> \
    'domain/TargetAccount$' -k -no-pass -u2u
```

This is only useful as the last piece of a larger chain — it doesn't grant
any access on its own. It matters when the account in question already
holds a Resource-Based Constrained Delegation grant from some other
computer object (verify that grant directly, e.g.
`msDS-AllowedToActOnBehalfOfOtherIdentity` on the delegating computer, rather
than assuming it — see [[hercules#Privesc|Hercules]] below for why), since
S4U2Proxy is what actually turns the resulting evidence ticket into a real
service ticket for an impersonated high-value user.

## Seen on

- [[hercules#Privesc|Hercules]] — `IIS_Webserver$`'s password was reset via
  a `Service Operators`-derived privilege, its TGT session key extracted,
  and its NT hash overwritten via `impacket-changepasswd -newhashes` to
  match that session key exactly. `DC$`'s `msDS-AllowedToActOnBehalfOfOtherIdentity`
  was independently confirmed (not assumed) to already grant
  `IIS_Webserver$` RBCD — the S4U2Self+U2U trick above then produced a real
  `administrator`-impersonating `cifs/dc.hercules.htb` ticket, which
  `impacket-secretsdump -just-dc-user administrator` turned into a DCSync
  of the real `Administrator` NT hash, without ever holding actual Domain
  Admin group membership.
