# Windows Credential Manager Can Hold a Different Account's Password

`cmdkey /list` inside any Windows logon context is a cheap, easy-to-forget
check the moment that context is reached for the first time — it isn't
only useful for the current account's own saved logins. A "Domain
Password" credential saved under one Windows account's Credential Manager
frequently belongs to a **different** identity entirely: an administrator
who once RDP'd/connected to another host "as someone else" and told
Windows to remember it. This is a genuine, common real-world pattern (an
admin's own workstation profile accumulating saved credentials for the
service/admin accounts they manage other machines with), not a
CTF-specific trick — and it's especially likely to survive long after the
*target* host it was scoped to (`Domain:target=<hostname>`) is
decommissioned, since nothing automatically expires a saved credential
just because its target stopped existing.

## Finding it

```
cmdkey /list
```
```
Currently stored credentials:
    Target: Domain:target=<some-host>.<domain>
    Type: Domain Password
    User: <a different account entirely>
```

If the target host still resolves and is reachable, the cheapest next step
is just connecting to it as the saved identity — Windows applies the
cached credential automatically. If it doesn't resolve (decommissioned,
never actually provisioned), the credential still needs decrypting
directly.

## Decrypting it: use `impacket`'s `dpapi.py`, not the generic Win32 APIs

Credential Manager's on-disk blob format (under
`%APPDATA%\Microsoft\Credentials\<hash>`) wraps the real DPAPI-protected
payload in an extra format-specific header. Generic calls
(`[System.Security.Cryptography.ProtectedData]::Unprotect`, raw P/Invoke
`CryptUnprotectData`) fail with `ERROR_INVALID_DATA` even after manually
locating and stripping that header, since Credential Manager needs its own
format-aware parsing layer these generic APIs don't implement.

`impacket`'s `dpapi.py` (`examples/dpapi.py`) does implement it, via two
subcommands chained together:

```
python3 dpapi.py masterkey -file <masterkey GUID file> -sid <owning account's SID> -password '<owning account's known password>'
# -> Decrypted key: 0x<hex>

python3 dpapi.py credential -file <credential blob> -key 0x<hex>
# -> [CREDENTIAL] Target / Username / <plaintext password>
```

The masterkey file to use is identified by matching the GUID in its
filename against the `guidMasterKey` field embedded in the credential
blob's own bytes (readable directly in a hex dump). **This decryption
requires the *owning* account's own logon secret** (or their real
password, as here) — not any account's elevated access, and not a
generically privileged context. A different, more-privileged identity
reached earlier in an engagement is not a shortcut past this: DPAPI's
per-user key material is derived from that specific user's own password,
so the credential can only be unlocked once that specific user's own
context (or known password) is in hand.

## Seen on

- [[DanglingTree#Privesc|DanglingTree]] — `noah.b`'s own Credential
  Manager (reached only via a genuine first-time logon as him, itself
  obtained via SmarterMail's decompiled `show-password` API) held a saved
  `alex.o` credential targeting a decommissioned host
  (`PC01.danglingtree.htb`). Decrypted via `noah.b`'s own already-known
  password unlocking his DPAPI masterkey chain, recovering `alex.o`'s real
  plaintext AD password and unblocking the rest of the engagement's path
  to root.
