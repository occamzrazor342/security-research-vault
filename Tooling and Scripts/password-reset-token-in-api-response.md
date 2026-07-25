# Password-Reset Token Returned In-Band, Not Just Sent Out-of-Band

The entire security value of a "forgot password" flow depends on the reset
token reaching the account holder through a channel the attacker doesn't
control — normally email or SMS. That property breaks completely if the
same token that gets emailed is *also* included in the HTTP response body
of the request-reset call itself. At that point the "out-of-band" step is
decorative: anyone who merely knows (or can enumerate) a valid account
identifier can read the token directly from their own HTTP client and skip
the mailbox entirely.

## How to spot it

- Call the forgot-password/request-reset endpoint yourself against a known
  or guessed account identifier (email/username) and read the **entire**
  response body, not just the status code. Don't assume "200 OK, no body
  shown in the UI" means nothing came back — inspect the raw JSON.
- Pay attention to backend code (if source is available) where a service
  function builds the reset link/token, calls the send-email function, and
  then also `return`s the same data object it just built — a classic
  "email as a side effect, but the object itself still flows back up the
  call stack to the HTTP handler" bug. The email call and the HTTP response
  are two independent places using the same in-memory object; forgetting to
  strip the sensitive fields before the `return` is enough.
- Check whether the endpoint sits on an authentication allowlist
  (`WHITELIST_URLS`-style config, `@Public()` decorators, route middleware
  that skips auth for specific paths) — request-reset endpoints usually
  have to be unauthenticated by design, which is exactly what makes a leak
  here unauthenticated too.
- A bonus tell: if the response *also* includes the account's password hash
  (not just the reset token) alongside "generic" account metadata, that's a
  strong sign the whole internal DTO/entity object is being serialized back
  to the client wholesale rather than a purpose-built response shape.

## Why it's a full account-takeover primitive, not just an info leak

Given only a valid email/username (often trivially discoverable via a
differing-error-message username-enumeration bug on the login endpoint
itself — 401 "wrong password" for a real account vs. 404 "not found" for a
fake one), an attacker can: request the reset, read the token straight out
of the JSON response, then call the reset-password endpoint with that
token to set a password of their choosing — full account takeover with zero
interaction with the victim's actual inbox, and no rate-limit or SMTP
misconfiguration would have closed the hole (a *working* mail server
doesn't help; the token is duplicated in-band regardless of whether the
email send succeeds).

## Seen on

- [[Silentium#Foothold|Silentium]] — Flowise 3.0.5's
  `POST /api/v1/account/forgot-password` (unauthenticated,
  `WHITELIST_URLS`) returned the full `AccountDTO` including
  `user.tempToken` and the bcrypt `credential` hash in the response body,
  identical to what `sendPasswordResetEmail()` sent out-of-band. Chained
  with login-endpoint username enumeration (401 vs. 404) to identify a real
  admin-role account (`ben@silentium.htb`) with only its name known from a
  public marketing page, then used the leaked token to reset its password
  and log in — the account takeover step that made the rest of the
  Flowise-to-host chain possible.
