# Contextual API Endpoint Discovery (Kiterunner-Style)

## Why generic content discovery structurally misses API routes

A traditional brute-forcer (`ffuf`, `feroxbuster`, `gobuster`) sends a bare
wordlist of path strings, almost always as `GET` with no body. Modern API
frameworks routinely require the *correct HTTP method plus a
syntactically-valid parameter value* just to avoid an immediate 404/405 —
before the app's own auth/business logic ever runs. A Flask-style route
like `/api/v1/notes/<int:key>` will 404 on every request unless the path
segment is actually an integer; a bare-word wordlist entry of
`/api/v1/notes` never reaches the real handler at all. This isn't a
depth/size problem (a bigger wordlist doesn't help) — it's a **wordlist-shape**
problem, the same category of gap as the files-vs-directories wordlist-family
issue already in `recon-agent`'s own checklist, just one level up the stack.

## The technique

Assetnote's `kiterunner` inverts the approach: instead of brute-forcing bare
path strings, it brute-forces **route + method + pre-filled parameter
values**, sourced from real OpenAPI/Swagger specs rather than invented by
hand. Their wordlist corpus (`routes-large.kite`) was built by mining
~67,500 real Swagger/OpenAPI documents — pulled from public GitHub repos
(via BigQuery), APIs.guru, SwaggerHub, and direct internet-wide scanning for
common spec paths (`/swagger.json`, `/api-docs.json`, `/v2/api-docs`, etc.)
— then compiled into routes carrying realistic UUIDs/integers/strings in
place of path parameters. The result finds real endpoints that no
hand-written wordlist would ever contain, because the wordlist is
effectively "every API route anyone has ever publicly documented," not a
guess at common naming conventions.

## How to apply it on a vault target

- Before brute-forcing any API surface (a `/api/`, `/v1/`, `/graphql`-style
  base path, or anything fingerprinted as a REST/JSON backend), check for a
  live spec first — `/swagger.json`, `/openapi.json`, `/api-docs`,
  `/v2/api-docs`, `/swagger-ui/`, `/redoc` — a found spec is strictly better
  than any wordlist, since it's the target's *actual* route list.
- If no spec is exposed, run `kiterunner` (`kr scan <target> -A
  <wordlist-alias>`) against the target rather than reaching for another
  pass of a generic directory wordlist — it tries each candidate route with
  its correct method and a plausible parameter value, so it will surface
  routes a bare-GET brute-forcer structurally cannot.
- This complements, rather than replaces, reading discovered JS bundles for
  hardcoded endpoint strings (already standard practice here) — a
  JS-bundle read finds routes *this specific app's frontend* calls; a
  kiterunner pass finds routes that exist on the backend whether or not the
  shipped frontend happens to call them.

## Source

Assetnote, "Contextual Content Discovery: You've Forgotten About the API
Endpoints" —
https://www.assetnote.io/resources/research/contextual-content-discovery-youve-forgotten-about-the-api-endpoints
; tool: https://github.com/assetnote/kiterunner

Not yet encountered on a vault box — added ahead of hitting it live, same
"learn it before you need it" instinct that made IIS shortname enumeration
(now a standing `recon-agent` checklist item) valuable once it was actually
needed.
