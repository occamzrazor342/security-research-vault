# Decrypting NiFi's `NIFI_PBKDF2_AES_GCM_256` Sensitive Properties Offline

Any NiFi controller-service property marked "sensitive" (a DBCP password,
an SMTP password, etc.) gets stored in `flow.xml.gz` as
`enc{<hex ciphertext>}` rather than plaintext, and NiFi's own REST API masks
it as `********` everywhere, including in the audit-history DB. If you have
read access to `flow.xml.gz` (or `flow.json.gz` on newer NiFi) **and**
`nifi.properties`' `nifi.sensitive.props.key` (the decryption key, stored in
plaintext by default unless `nifi.sensitive.props.key.protected` is also
set), the ciphertext is fully recoverable offline — no NiFi process access
needed.

## Mechanism (reverse-engineered from NiFi source, `nifi-commons/
nifi-property-encryptor` and `nifi-commons/nifi-security-utils` at the
relevant release tag — not from a blog paraphrase)

- **Key derivation:** `PBKDF2WithHmacSHA512(sensitive.props.key,
  salt=b"NiFi Static Salt", iterations=160000, dklen=32)`. The salt is a
  hardcoded static value baked into NiFi itself — not per-installation,
  not per-value.
- **Ciphertext format:** `hex(16-byte random IV || AES/256/GCM
  ciphertext+tag)`. The IV is unique per encrypted value; the derived key
  is the same for every sensitive property in the same NiFi instance.
- **Decrypt:** split the hex-decoded bytes into the first 16 bytes (IV) and
  the rest (ciphertext+tag), then `AES-256-GCM` decrypt with the derived
  key. GCM's authentication tag verifying successfully on decrypt is itself
  cryptographic proof the recovered plaintext is correct — not a guess, a
  provable match.

```python
import hashlib, re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_nifi_sensitive(enc_value: str, sensitive_key: str) -> str:
    hexblob = re.match(r"enc\{(.+)\}", enc_value).group(1)
    raw = bytes.fromhex(hexblob)
    iv, ct = raw[:16], raw[16:]
    key = hashlib.pbkdf2_hmac(
        "sha512", sensitive_key.encode(), b"NiFi Static Salt",
        160000, dklen=32,
    )
    return AESGCM(key).decrypt(iv, ct, None).decode()
```

## Where to find the two inputs

- `enc{...}` values: `zcat flow.xml.gz | grep -A2 "<name>Password</name>"`
  (or equivalent for whichever sensitive property).
- `nifi.sensitive.props.key`: plaintext in `nifi.properties` unless
  `nifi.sensitive.props.key.protected` is set (in which case the key itself
  needs a separate unwrap step not covered here).

## Caveat this doesn't solve

Recovering the plaintext is guaranteed correct for *that specific
controller-service credential* — it says nothing about whether that
credential is reused anywhere else (a DB user, an OS account, etc.). Treat
it as one candidate to test broadly, not a confirmed pivot on its own.

## Seen on
[[Helix#Privesc|Helix]] — recovered the `operator` DBCP password
(`R7qZ9L3xKM2W8pFYcA`) from `flow.xml.gz` this way; the recovery was
cryptographically airtight but the credential turned out not to be shared
with the OS `operator` account (a deliberate red herring in that box's
design) — see that writeup's Rabbit Holes for the full story.
