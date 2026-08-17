# CBC Padding-Oracle Forgery of a Trusted Encrypted Value

## Why "encrypted" isn't "authenticated"

Encrypting a value (a `parentid`, a session/state parameter, a "signed"
token that's actually just ciphertext) with AES-CBC stops a passive observer
from reading it, but CBC alone provides zero integrity guarantee — nothing
stops an attacker from flipping bits or brute-forcing the plaintext if the
application leaks *any* signal about whether a decrypted value was
well-formed. The most common leak is padding validation: PKCS#7 padding
requires the last *n* bytes of a decrypted block to each equal the value
*n*, and an app that throws a distinguishable error (different exception,
status code, timing, or response body) when that check fails versus when it
passes hands an attacker a **padding oracle** — a yes/no primitive that,
applied one byte at a time, byte-flips its way to full plaintext recovery
and, further, to **forging entirely new ciphertexts the app will decrypt
successfully to attacker-chosen plaintext**, all without ever knowing the
key.

## The mechanism (classic CBC byte-flipping via a padding oracle)

For any two adjacent ciphertext blocks `C[i-1]` and `C[i]`, decryption
computes `P[i] = D(C[i]) XOR C[i-1]`. An attacker who controls `C[i-1]`
(a chosen "IV"-like preceding block) can iterate all 256 values for its
last byte and submit `C[i-1] || C[i]` to the target; the one value that
produces *valid* padding (no error) reveals `D(C[i])`'s last byte via
`D(C[i])[last] = triedByte XOR 0x01`. Repeating per byte, then per block,
recovers the full plaintext of `C[i]` — and by construction the reverse
also works: an attacker can pick *any* desired plaintext and compute a
`C[i-1]` that decrypts to it, forging a ciphertext for a value they were
never supposed to be able to set (e.g. a `parentid` pointing at a resource
outside their tenant), still with no knowledge of the actual key.

## How to spot it

- Any parameter that looks like base64/hex ciphertext (high entropy, length
  a multiple of 16 bytes) and is decrypted server-side before being trusted
  — test it first, before assuming it needs the key to forge.
- Submit syntactically-mangled versions of the value (flip a byte in the
  last block) and diff the responses/errors against a well-formed baseline.
  A distinguishable "bad padding"/"decryption failed"-style error (vs. a
  generic "not found"/business-logic error for a validly-padded-but-wrong
  value) is the oracle.
- Tools: `padbuster`/PortSwigger's own decrypter workflow automate the
  byte-at-a-time recovery/forgery once an oracle is confirmed — don't
  hand-roll this from scratch.

## Source

Assetnote, "Encrypted Doesn't Mean Authenticated: ShareFile RCE
(CVE-2023-24489)" —
https://www.assetnote.io/resources/research/encrypted-doesnt-mean-authenticated-sharefile-rce-cve-2023-24489

Not yet encountered on a vault box — this is a decades-old classical
technique (POODLE-era padding-oracle theory applied to an app-level value
rather than TLS itself), but it was absent from this vault's own index
entirely until now, which is itself worth noting: a technique doesn't have
to be novel to be a real gap.
