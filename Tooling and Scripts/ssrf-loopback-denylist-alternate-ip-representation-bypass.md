# SSRF Loopback-Denylist Bypass via Alternate IP Representations

A backend that "blocks SSRF" by checking whether a user-supplied URL's host
is the literal string `127.0.0.1` or `localhost` is checking the string it
was handed, not the address that string actually resolves to. Any parser
downstream (the language's own URL/socket-resolution code) that accepts
looser IP syntax than the denylist's author anticipated turns every one of
those alternate spellings into a live bypass.

## Representations worth testing

All of these resolve to `127.0.0.1` in most standard libc/URL-parsing
implementations, but a naive string-equality or short-regex denylist
typically only catches the first one or two:

- **Shorthand IPv4** — `127.1` (a 2-part address; the last part is treated
  as a 24-bit value filling the remaining octets)
- **All-zeros shorthand** — `0.0.0.0` (binds-all address, but as a
  *connect* target on most stacks resolves to loopback)
- **Zero-padded octets** — `127.000.000.001`
- **Octal** — `0177.0.0.1` (leading `0` triggers octal parsing per-octet)
- **Decimal (32-bit integer) form** — `2130706433`
- **Hex** — `0x7f.0.0.1` or the fully-packed `0x7f000001`
- **IPv4-mapped IPv6** — `[::ffff:127.0.0.1]`
- **Domain names that resolve to loopback** — `localtest.me`,
  `127.0.0.1.nip.io`, or an attacker-controlled DNS record pointed at
  `127.0.0.1` (rebinding-adjacent, but the same "denylist checks the
  string, not the resolved address" root cause)

Some targets separately still block a *subset* of these (e.g. bare
`[::1]` or the literal `localhost` string specifically) while letting
everything else through — worth testing the full list rather than
concluding "loopback is blocked" after only the most obvious form fails.

## Practical workflow

1. Confirm the SSRF primitive exists at all with an external URL that the
   backend can plausibly reach (or, if there's no outbound internet, one
   that at least proves a fetch attempt happened — e.g. a distinct timeout
   or connection-refused response shape vs. a validation-error response).
2. Try the literal loopback string first — if blocked, the message/error
   shape often reveals whether the check is string-based ("that address is
   not permitted") vs. resolution-based ("connection refused" would imply
   it actually tried to connect and got rejected downstream instead).
3. Sweep the representations above. The first one that returns a
   *different* response shape than the blocked case (a real fetch result,
   a different error, a longer delay) is a working bypass.
4. Once one loopback bypass works, use it for internal port/service
   discovery (`http://<bypass-form>:<port>`) — treat this exactly like
   unauthenticated internal recon, not a one-off curiosity.
5. Check whether the SSRF only supports `GET` (many "URL validator"/
   "source checker" style endpoints do) before assuming it can drive
   anything requiring a different method or a protocol upgrade
   (WebSocket handshakes, authenticated POSTs) — if so, use it purely for
   recon (reading internal-only GET endpoints, mapping the internal
   service graph) and pivot to a direct connection once an internal
   Host-header-routed vhost or reachable port is identified.

## Seen on

- [[Cohort#Foothold|Cohort]] — `POST /api/validate`'s `url` parameter
  blocked the literal strings `127.0.0.1`/`localhost` but let `127.1`,
  `0.0.0.0`, octal/decimal/hex forms, zero-padded octets, and IPv4-mapped
  IPv6 straight through. Used to enumerate internal ports and to read an
  externally-403'd nginx `/status` page, which named an internal-only
  vhost (`nb-<hex>.cohort.htb`) that turned out to be directly reachable
  from outside once its name was known (nginx routes by Host header
  regardless of how that Host string was discovered).
