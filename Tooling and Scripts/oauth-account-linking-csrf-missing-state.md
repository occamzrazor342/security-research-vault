# OAuth account-linking CSRF via a missing `state`/PKCE parameter

## Why this is a distinct bug class from "OAuth login CSRF"

The classic, well-known version of this bug (CSRF on the OAuth
Authorization Code flow, RFC 6749 §10.12) is usually framed as **login
CSRF**: an attacker mints a code for their own IdP identity, tricks a
victim's *unauthenticated* browser into visiting the relying party's
callback with that code, and the victim ends up logged into the attacker's
account without realizing it — useful for tricking someone into
unknowingly using an attacker-monitored account, but not itself an
account-takeover of the victim's real identity.

**Account-linking CSRF is the same missing-`state` root cause aimed at a
different, often higher-impact target.** Many apps let an *already
logged-in* user link their existing account to a third-party IdP identity
for password-less login later ("Connect your Google/Qooqle account"). If
the callback endpoint that performs that link doesn't verify the session
visiting it is the same session that initiated the `/authorize/` request
(exactly what `state` is for), then:

1. The attacker authenticates to the IdP as **themselves** and mints a
   valid authorization code for their **own** identity.
2. The attacker gets a **victim's already-authenticated** session on the
   relying party to visit the callback URL with that code (no click/JS
   needed if there's any same-origin forced-navigation primitive available
   — a stored `<meta http-equiv="refresh">`, an open redirect, a CSTI
   trigger, etc.).
3. The relying party's callback handler links the **victim's** account to
   the **attacker's** IdP identity, because nothing checked that the
   session performing the link matches the session that started the OAuth
   dance.
4. The attacker now logs into the relying party "via IdP" using their own
   IdP credentials and lands directly in the **victim's** account — full
   session takeover, not just "victim uses attacker's account."

## How to spot it

- Check whether the relying party's own `/authorize/` initiator ever sends
  a `state` (or PKCE `code_challenge`) parameter at all:
  ```
  GET /accounts/oauth2/<provider>/authorize/
  -> 302 Location: https://<idp>/oauth2/authorize/?client_id=...&response_type=code&redirect_uri=...
  ```
  No `state=`/`code_challenge=` in that redirect is the tell.
- Confirm the callback endpoint's behavior doesn't depend on any
  session-bound value from step 1 — mint a code as your own IdP identity,
  then hit the callback directly from a **different** session/cookie jar
  and confirm it still processes the link/login rather than rejecting it
  for a missing/mismatched `state`.
- Authorization codes are normally short-lived (in the tens of seconds) —
  don't pre-mint a code and hope a delivery mechanism of unknown latency
  reaches the callback before it expires. Instead, build a **just-in-time
  minting redirector**: an attacker-controlled endpoint that, on any
  inbound hit, mints a *fresh* code in real time and then 302s the
  requester straight to the vulnerable callback with that fresh code. This
  removes the code-TTL race entirely, since the code isn't minted until the
  delivery mechanism has actually fired.

## Delivery still has to land an already-authenticated session on the callback URL

The vulnerability itself doesn't solve delivery — you still need *some*
mechanism that gets a privileged, already-logged-in session's browser to
navigate to the callback URL. This is usually the harder half in practice;
see [[Eloquia#Foothold|Eloquia's writeup]] for a full worked example where
the OAuth bug itself was confirmed and weaponized (via a just-in-time code
minter) hours before an actual delivery trigger was found for it, and for
the specific lesson about not assuming which account/report-identity
pattern a "report this content to a human/bot reviewer" feature expects.

## Reusable tooling

`Tooling and Scripts/exploits/eloquia/oauth_redirector.py` — the
just-in-time code-minting redirect listener referenced above; adaptable to
any `django-oauth-toolkit`-style (or generically RFC 6749) target by
swapping the code-mint request and the vulnerable callback URL.
