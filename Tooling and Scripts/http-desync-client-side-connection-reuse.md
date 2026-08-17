# Client-Side Desync (Browser-Powered Request Smuggling)

## Why this is a distinct bug class from classic CL.TE/TE.CL smuggling

Classic HTTP request smuggling exploits a **front-end/back-end disagreement**
about where one request ends and the next begins (a load balancer using
`Content-Length`, an app server using `Transfer-Encoding`, or vice versa) —
it requires two servers in the chain and doesn't apply to a single-server
site.

**Client-side desync (CSD) needs no second server at all.** It desyncs the
*browser's own connection* to a single vulnerable site. The exploited quirk
is a server that responds to a POST **before fully consuming the body it
declared via `Content-Length`**: the unread body bytes stay buffered on the
underlying TCP/TLS socket. If the browser's connection pool then reuses that
same socket for the *next* request (any browser does this by default for
performance), the leftover bytes get prepended onto that next request from
the server's point of view — so the server parses
`[attacker-chosen leftover bytes] + [browser's real next request]` as if it
were one thing, with the leftover bytes able to smuggle in an entirely
different request line/headers/body ahead of whatever the browser actually
sent.

## How to spot it

- Send a POST with a `Content-Length` **larger** than the actual body you
  send, then check whether the server responds anyway rather than waiting
  for/timing out on the missing bytes. A response is the tell — it means
  those declared-but-unsent bytes are still sitting on the socket for the
  *next* request to inherit.
- This is meaningfully different from probing server-to-server smuggling —
  no second server/proxy needs to exist, so it's worth trying against
  single-origin apps that would otherwise look like poor request-smuggling
  candidates.
- PortSwigger's `http-request-smuggler` Burp extension (v3.0+, 2025) added
  parser-discrepancy detection specifically to catch these cases even
  behind modern desync-hardened front ends.

## What it buys you

Once a follow-up request's prefix is attacker-controlled, the usual
smuggling payloads apply: poisoning another user's next response on that
connection (if the server/proxy is shared — an internal network, a corporate
VPN gateway, a CDN edge), planting a malicious response in a cache
(pairs directly with
[[web-cache-poisoning-unkeyed-input-and-web-cache-deception]]), or,
in a browser-specific twist, "poisoning" the *victim's own browser's*
connection pool so a subsequent same-origin request from that victim's
tab gets the attacker's injected response instead of the real one —
useful for stored/persistent XSS-like impact against a single victim with
no server-side smuggling required at all.

## Source

PortSwigger Research, "Browser-Powered Desync Attacks: A New Frontier in
HTTP Request Smuggling" (2022) and the ongoing series ("HTTP/2: The Sequel
is Always Worse", "HTTP/1.1 Must Die! The Desync Endgame") —
https://portswigger.net/research/browser-powered-desync-attacks ;
Web Security Academy: https://portswigger.net/web-security/request-smuggling/browser
and https://portswigger.net/web-security/request-smuggling/browser/client-side-desync

Not yet encountered on a vault box — added from PortSwigger research ahead
of hitting it live, per the same "learn it before you need it" instinct
that made IIS shortname enumeration valuable once it was actually needed.
