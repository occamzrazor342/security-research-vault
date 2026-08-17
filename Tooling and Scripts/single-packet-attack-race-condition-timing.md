# The Single-Packet Attack (Remote Race Conditions Made Local)

## The problem it solves

Exploiting a web race condition (redeeming a coupon twice, transferring
funds from an account past its balance, hitting a "one-time" action
multiple times) needs two or more requests to arrive at the server
**close enough together** that its check-then-act logic runs concurrently
instead of sequentially. Just firing requests in parallel from a normal
HTTP client is limited by real network jitter — over any real network path,
concurrently-sent requests still land server-side with enough spread that
many race windows (sub-millisecond ones especially) never get hit.

## Predecessor: last-byte sync (HTTP/1.1)

The older technique withholds the final byte of each request's headers,
sends all-but-that-byte for every request first, waits for them to be
queued server-side, then releases every withheld last byte back-to-back.
This tightens timing a lot over naive parallel firing but is still
byte-level, connection-per-request, and only as tight as the sequence of
individual `send()` calls releasing those bytes actually is.

## The single-packet attack (HTTP/2)

HTTP/2 multiplexes many request streams over one TCP connection. This
technique withholds a tiny final fragment of *every* request stream on a
single HTTP/2 connection, waits briefly, then releases all the withheld
fragments in one call — the OS network stack coalesces them into a
**single TCP packet**. Since every request's trigger byte physically
arrives in the same packet, the server necessarily processes them
essentially simultaneously — there's no longer a sequence of separate
network events for jitter to act on at all. This is reported to squeeze
~30 requests sent across a real long-haul link (Melbourne→Dublin) into a
sub-1ms server-side processing window — turning a remote race condition
into one that behaves like a local, same-host race.

## Practical use

- **Burp Suite Repeater** supports this natively via its request
  "group and send in parallel (single packet attack)" tab-group option —
  no separate tooling needed for ad hoc testing once HTTP/2 is confirmed
  available against the target.
- **Turbo Intruder** (PortSwigger's scripting-based Intruder alternative)
  supports both last-byte sync and single-packet attack engines
  programmatically, useful when the race needs many requests or precise
  per-request parameter variation rather than N copies of one request.
- Requires the target to support HTTP/2 (check via `curl -I --http2` or the
  ALPN negotiated in the TLS handshake) — against an HTTP/1.1-only target,
  last-byte sync is the fallback, not this technique.

## Where to look for the underlying bug, once timing is solved

This technique only wins the *timing* half — the actual bug is still a
missing lock/transaction around a check-then-act sequence. High-yield spots
per PortSwigger's "Smashing the State Machine" research: multi-step flows
with hidden intermediate states (partial registration/2FA flows, OAuth
callback handling), any "redeem code"/"use one-time X" endpoint, and
subtle logic beyond simple limit-overrun — e.g. racing a password
reset/email-change confirmation against the request that generated it, or
racing two different endpoints that touch the same underlying state rather
than sending N copies of the identical request.

## Source

PortSwigger Research, "The Single-Packet Attack: Making Remote Race
Conditions 'Local'" and "Smashing the State Machine: The True Potential of
Web Race Conditions" (James Kettle, Black Hat USA '23 / DEF CON 31) —
https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local
and https://portswigger.net/research/smashing-the-state-machine

Not yet encountered on a vault box — added from PortSwigger research ahead
of hitting it live.
