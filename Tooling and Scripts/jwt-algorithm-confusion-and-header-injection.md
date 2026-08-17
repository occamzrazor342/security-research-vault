# JWT Algorithm Confusion and Header-Injection Attacks

JWT verification bugs worth checking on any app that hands a client a
`header.payload.signature` token and trusts it back on later requests
without a server-side session store backing it. All of these are
**signature-bypass** primitives — the goal is a token with attacker-chosen
claims (role, user id, etc.) that still verifies as legitimate.

## `alg: none` (unsecured JWT)

The JWS/JWT spec defines `none` as a legitimate `alg` value for an
explicitly *unsigned* token — the signature segment is simply empty (the
token ends in a trailing `.` with nothing after it). Some libraries and a
lot of hand-rolled verifiers implement `alg` as a runtime dispatch (`if alg
== "HS256": verify_hmac(...) elif alg == "none": accept unconditionally`)
without ever pinning which algorithms are actually acceptable for a given
deployment — so setting `alg: none` in a forged token's header and
supplying whatever claims you want (`role: admin`, etc.) with no signature
at all is enough to pass verification outright.

Forging one needs no cryptography:

```python
import base64, json

def b64url(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin"}
token = b64url(header) + "." + b64url(payload) + "."   # trailing dot, empty signature
```

A service that self-reports its supported algorithms in any
unauthenticated status/version/docs endpoint (`"supported_algorithms":
["HS256","none"]`) is handing you the answer before you've tried anything —
treat `none` appearing in such a list as an immediate, directly-testable
signal rather than something to infer from behavior first. Some verifiers
also gate on the *header's* `alg` case-sensitively or via naive string
matching, so if a straightforward `none` gets rejected it's worth also
trying case variants (`None`, `NONE`) per PortSwigger's own findings below.

## Algorithm confusion (RS256 → HS256 downgrade)

Many JWT libraries expose one generic `verify(token, key)` call whose actual
verification behavior (symmetric HMAC vs. asymmetric RSA/EC signature
check) is decided **at runtime by the token's own `alg` header** rather than
being pinned by the caller. If the server was written expecting only
RS256 (asymmetric: private key signs, public key verifies) and passes its
**public** key into that generic `verify()` call, an attacker who sets
`alg` to `HS256` in a forged token causes the library to treat that same
public key as a **symmetric HMAC secret** instead — and since the public
key is, by definition, not secret, the attacker can compute a valid HS256
signature over any payload they want using it.

**Getting the public key:**
- Directly exposed at `/jwks.json` or `/.well-known/jwks.json` (a JWK Set —
  an array under a `"keys"` field).
- If not exposed, tools like `jwt_forgery.py` can **derive** the public key
  purely from two existing RS256-signed tokens the app already issued (no
  private-key material needed).
- Format matters exactly — convert to PEM (X.509 vs. PKCS1) and match
  byte-for-byte, including non-printing characters, or the HMAC computation
  won't match what the server derives internally.

**Building the forged token:** set `alg: HS256` in the header, set whatever
claims are wanted in the payload, then HMAC-sign the
`base64url(header).base64url(payload)` string using the recovered public key
(in its exact matching string form) as the HMAC key.

## `jwk`/`jku`/`kid` header-injection variants

Separate from algorithm confusion, three more JWT header fields are
attacker-editable in a naive verifier and each is its own bug class:

- **`jwk` (embedded key):** the header can carry the *entire verification
  key* inline as a JSON Web Key object. If the server trusts whatever key
  is embedded in `jwk` rather than only its own known key(s), an attacker
  just generates their own keypair, signs the forged token with their
  private key, and embeds their matching public key in the `jwk` header —
  the server verifies "successfully" against a key the attacker fully
  controls.
- **`jku` (key-set URL):** the header points the server at a URL to fetch
  the verification key set from. If that URL isn't allowlisted against the
  server's own trusted domain, host an attacker-controlled JWK Set at a URL
  you control and point `jku` at it — same outcome as embedded `jwk`, one
  layer removed.
- **`kid` (key ID):** used to select which key from a multi-key store to
  verify against. If `kid` is used to build a filesystem path or DB/cache
  lookup key without sanitization, it's an injection primitive in its own
  right — path traversal (`kid: ../../../../dev/null`, paired with an
  HS256 token signed with an empty/known string, since some verifiers treat
  a lookup failure as "verify against this fallback") or SQL injection
  (`kid` value dropped straight into a `SELECT key FROM keys WHERE
  id='<kid>'`-style query).

## How to spot it

- Decode the header/payload (base64url, no signature verification needed)
  of any JWT the app issues and check which of `alg`/`jwk`/`jku`/`kid` are
  present — presence of any of the latter three is worth testing
  immediately, presence of `RS256`/`ES256` is worth testing for the
  downgrade, and any `alg` at all is worth testing the `none` swap on
  regardless of what the original token used.
- For the downgrade specifically: confirm the server actually re-derives
  its own key material at verify time from something identifiable as "the
  RS256 public key" (a `/jwks.json`, a cert, a config value) before
  assuming the attack applies — a server that pins the verification
  algorithm itself (ignoring the token's own `alg` header) isn't
  vulnerable regardless of what the token claims.
- For `alg: none` specifically: check any unauthenticated status/version
  endpoint the service exposes first — a self-reported algorithm list is a
  much stronger and faster signal than blind testing.

## Source

Web Security Academy, "JWT attacks" — algorithm confusion, `jwk`/`jku`/`kid`
header parameters, and the `none` algorithm —
https://portswigger.net/web-security/jwt,
https://portswigger.net/web-security/jwt/algorithm-confusion, and
https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported

The RS256→HS256 downgrade and `jwk`/`jku`/`kid` variants were added from
PortSwigger research ahead of hitting them live and remain unconfirmed on a
vault box. The `alg: none` case was confirmed live on
[[Fireflow#Privesc|Fireflow]] — an internal "MCP AI Tool Registry"
microservice self-disclosed `"none"` as a supported algorithm in its own
unauthenticated version banner, and a signature-less forged token with
`role: admin` passed its `require_admin` check outright, unlocking an
admin-gated arbitrary-code-registration endpoint with no credentials at
all.
