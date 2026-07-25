# Capturing a Service's Real Credential by Redirecting Its Own Auth Target, Not Decrypting Its Stored Secret

When you have write access to a service's config file (root inside its
container, a writable config volume, etc.) and that config stores a
downstream credential in some internally-encrypted or otherwise
non-trivially-reversible form, decrypting it offline isn't the only path to
the plaintext. If the service (a) self-reloads on config changes and (b)
will re-establish its downstream connection using that credential the next
time it needs to, you can point the config's target address at an
attacker-controlled listener and let the service hand you its own plaintext
credential the next time it authenticates.

## Why this beats attacking the encryption directly

Reversing an app's internal secret-encryption scheme (its own symmetric
key, key-derivation process, etc.) is a real research effort with no
guarantee of success, and is usually unnecessary: the application doesn't
need to decrypt anything differently to fall for this — it just needs to
open a connection using the credential it already has, against whatever
address its config currently says to use. The technique treats the
downstream service address as the actual variable under attacker control,
not the secret.

## Mechanism

1. **Confirm the config self-reloads.** Many apps watch their own config
   file for changes and hot-restart (check the config's own comments/docs,
   or just test it) — this avoids needing a separate service-restart
   trigger.
2. **Back up the original config**, then edit only the field pointing at
   the downstream service's address (an LDAP server URL, a database host,
   an upstream API endpoint, etc.) to an attacker-controlled
   listener/port. Leave every other setting, including the encrypted
   credential itself, untouched.
3. **Stand up a minimal protocol-aware listener** for whatever the
   downstream protocol is — it doesn't need to be a real backend, just
   enough of the protocol to receive the auth exchange and log the
   credential in the clear (e.g. a raw LDAPv3 `BindRequest` BER parser
   that logs the bind DN + simple-bind password and always replies
   "invalid credentials" so the calling app fails over cleanly rather than
   hanging).
4. **Trigger a real auth attempt.** A config reload alone often isn't
   enough if the service initializes its downstream connection lazily
   (only on first actual use, not eagerly at startup/restart) — drive
   whatever user-facing action actually requires that downstream
   connection (e.g. a login attempt against the app itself).
5. **Cross-verify the capture is authentic**, not a decoy or an unrelated
   connection — the target application's own error/diagnostic output for
   the resulting (intentionally failed) attempt should echo the same
   identity/DN your listener captured, confirming this really is the
   credential the app tried to use.
6. **Restore the original config immediately** and verify the restoration
   (don't just assume the `cp`/`docker cp` back succeeded).

## Seen on

- [[fries#Privesc|Fries]] — PWM's `ldap.proxy.password` was stored
  internally-encrypted (`ENC-PW:...`) with no offline decryption path found
  after a full source audit; editing the writable, self-reloading
  `PwmConfiguration.xml`'s `ldap.serverUrls` to point at an attacker LDAP
  listener, then firing a real login attempt against PWM's own login page,
  captured the real plaintext `svc_infra` bind password in the clear — the
  first working AD domain credential recovered in the entire engagement.
