# Web Cache Poisoning and Web Cache Deception

Two distinct bugs that share the same root cause: **the cache's idea of
what makes two requests "the same" (its cache key) doesn't match how the
origin server actually decides what to send back.** Worth checking both any
time a target sits behind a caching layer (CDN, reverse-proxy cache,
`Cache-Control`-respecting app server) — which is close to a default
assumption for anything public-facing now.

## Web cache poisoning — unkeyed input reaches a keyed response

Most caches key on method + path (+ maybe a few headers) but forward the
**entire** request — including headers/params the cache doesn't key on —
to the origin. If the origin's response actually varies based on one of
those unkeyed inputs (a classic offender: reflecting `X-Forwarded-Host` or
`X-Forwarded-Scheme` into a canonical-URL `<script>` tag, or a Host header
reflected into an absolute-URL redirect), an attacker can send one poisoned
request that gets cached under a **normal-looking, high-traffic cache key**
(e.g. plain `GET /`) — every subsequent visitor requesting that same path
gets the poisoned response until the entry expires or is purged.

**How to spot it:** for every header/param that's reflected anywhere in a
response (check `X-Forwarded-*`, `X-Original-URL`, `X-Rewrite-URL`, `Host`,
`Accept-Language` first), confirm the cache actually varies output on it
(different value → different response) *and* that the cache key does **not**
include it (same `Cache-Control`/cache-hit indicator across two requests
differing only in that header). Both conditions have to hold — reflected-but-
keyed is not exploitable this way.

**2024 research ("Gotta Cache 'em all") added two higher-yield variants**
worth checking specifically:
- **Fat GET requests** — a GET with a request body, sent through a cache
  (Varnish especially) paired with a backend framework that reads params
  from the body even on GET. The body isn't part of the cache key by
  default, so it's a free unkeyed-input channel most testers never try
  since "GET requests don't have bodies" is the common (wrong) assumption.
- **Path normalization discrepancies** — traversal-style segments
  (`/..;/`, double-encoded `%2e%2e`, etc.) that the cache normalizes away
  when computing its key but the origin (or an intermediate proxy) resolves
  differently, letting a poisoned response for one path get served under a
  completely different, high-value path's cache key (e.g. poisoning
  `/home`).

## Web cache deception — the inverse bug

Instead of getting the cache to store an *attacker's* malicious response
under someone else's key, cache deception tricks the cache into storing
**a real victim's own sensitive, dynamic response** under a URL the cache
treats as static/cacheable — then the attacker just requests that same URL
and reads it back.

**Mechanism:** append something that looks like a static-asset path segment
to a real dynamic/authenticated endpoint, e.g.
`GET /my-account/settings.js` or `GET /my-account%2f..%2fnonexistent.css`.
If the cache's "is this cacheable" decision is based on a naive suffix/
extension check on the URL, while the *origin* ignores the bogus trailing
segment and serves the real dynamic page anyway (common with path-info-style
routing), the cache stores that authenticated response under the
attacker-guessable static-looking URL. Get a victim to visit that exact
crafted link once while logged in, then request the same URL yourself —
the cache serves you their session's response.

## How to confirm either, cheaply

Send two requests differing only in the suspected unkeyed dimension and
diff the cache-status indicator (`X-Cache: hit/miss`, `Age` header, or
response-timing) against the response body itself — a cache **hit** with a
body that should have changed (poisoning) or a cache **hit** on a URL that
should never be publicly cacheable at all (deception) is the confirming
signal, not just "the reflection/routing quirk exists in isolation."

## Source

PortSwigger Research: "Practical Web Cache Poisoning" (2018), "Web Cache
Entanglement: Novel Pathways to Poisoning" (2020), and "Gotta Cache 'em All:
Bending the Rules of Web Cache Exploitation" (Black Hat USA 2024) —
https://portswigger.net/research/practical-web-cache-poisoning ,
https://portswigger.net/research/web-cache-entanglement ,
https://portswigger.net/research/gotta-cache-em-all ;
Web Security Academy: https://portswigger.net/web-security/web-cache-poisoning
and https://portswigger.net/web-security/web-cache-deception

Not yet encountered on a vault box — added from PortSwigger research ahead
of hitting it live.
