# Client-Side Path Traversal to CSRF (CSPT2CSRF)

## Why this is a distinct bug class

Client-side path traversal (CSPT) is frontend JS building an API request URL
by concatenating a base path with user-controlled input (a URL fragment,
query param, or even data already stored server-side) without normalizing
`../` sequences first — so the *browser's own JS* sends its XHR/fetch call
to a different path than the developer intended, entirely client-side, no
server-side traversal bug required. On its own this has long been dismissed
as low-impact ("so the frontend calls a different GET endpoint, so what"),
which is exactly why it went largely undocumented — a handful of scattered
bug reports existed, but no general exploitation framework. The Doyensec
research supplies that framework by chaining it into CSRF impact.

## The chaining mechanism

1. **Source**: find where attacker-controlled input flows into a path that
   frontend JS builds for an API call — URL fragments/query params are the
   classic source, but a stored value that later gets rendered into a
   path-building context also counts.
2. **Sink**: the frontend fires a request to that attacker-influenced path.
   A GET-only sink looks harmless in isolation (it just misdirects a read).
3. **The elevation step**: use the traversal to redirect that GET at a
   *different* JSON response the attacker controls the content of (e.g. via
   a file-upload gadget, or any endpoint reflecting attacker data as JSON),
   then rely on the frontend's own logic to parse that JSON response and
   fire a **second, state-changing** request (POST/PUT/DELETE) using fields
   taken from what it just fetched. The victim's browser makes both
   requests with real, legitimate session cookies attached — nothing about
   this trips CSRF-token or SameSite defenses, because every request
   genuinely originates from the victim's own authenticated session; only
   the *path* of the first request was attacker-steered.

The net effect: an app that has CSRF protection correctly implemented on its
real state-changing endpoints can still be fully CSRF-exploitable if any
GET-only client-side traversal exists that a chained fetch can be routed
through — the traversal is doing the job an explicit CSRF bug would normally
have to do.

## How to spot it

- Grep frontend bundles for URL/path construction that concatenates
  location/history/query-param values without a `../`-normalizing step first
  (`fetch(base + userControlledSegment)`-shaped code, router logic that
  builds API paths from route params).
- Any SPA route or URL fragment that ends up substituted into an API base
  path is worth traversal-testing (`../../../other/endpoint`) even if the
  only visible effect looks like "wrong GET happened" — that's the low-impact
  presentation this bug class hides behind.
- Once a GET-redirect via traversal is confirmed, check what the frontend
  *does* with that response — specifically, whether any field from the
  fetched JSON gets used to construct a follow-up request. That follow-up is
  the actual CSRF payload delivery mechanism.

## Source

Doyensec, "Exploiting Client-Side Path Traversal to Perform Cross-Site
Request Forgery - Introducing CSPT2CSRF" (2024) —
https://blog.doyensec.com/2024/07/02/cspt2csrf.html ;
resource index: https://blog.doyensec.com/2025/03/27/cspt-resources.html

Not yet encountered on a vault box — added from published research ahead of
hitting it live, same instinct that made IIS shortname enumeration valuable
once it was actually needed.
