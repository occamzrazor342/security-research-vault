# Apache httpd "Confusion Attacks" (Module Semantic Ambiguity)

## Why this is a distinct bug class

Apache httpd's request lifecycle passes a single shared `request_rec` struct
through dozens of modules (core, `mod_rewrite`, `mod_proxy`, `mod_authz_core`,
CGI/FastCGI handlers, ...), each free to read and mutate its fields. The
modules don't agree on what those fields *mean* — the same field
(`r->filename`, `r->content_type`/handler) gets treated as a raw filesystem
path by one module and as a URL by another. Nothing in httpd's design forces
agreement; each module was written independently over decades and just
trusts whatever the previous one left behind. That's a **semantic ambiguity
between trusted components**, not a memory-safety bug or an input-validation
miss in any single module — closer in spirit to the request-smuggling family
([[http-desync-client-side-connection-reuse]]) than to a classic injection
bug, just with modules-in-a-process instead of hops-on-a-wire disagreeing
about the same data.

## Three concrete mechanisms (Orange Tsai, "Confusion Attacks", 2024)

- **DocumentRoot escape via `RewriteRule`.** A rewrite target gets probed both
  relative to and outside `DocumentRoot`. `RewriteRule "^/html/(.*)$"
  "/$1.html"` plus a request for `/html/usr/share/libreoffice/help/help.html%3F`
  — the trailing `%3F` (a literal `?`) truncates the appended `.html`, and
  httpd resolves the *absolute* path `/usr/share/libreoffice/help/help.html`
  outside the web root entirely (world-readable on stock Debian/Ubuntu),
  handing back an arbitrary-file-read primitive from what looks like an
  ordinary rewrite rule.
- **ACL bypass with a single `?`.** A `<Files "admin.php"><Require
  valid-user></Files>` block matches on `r->filename` as a literal
  string — `admin.php%3Fooo.php` doesn't match `admin.php` so the ACL waves
  it through. But `mod_proxy` (fronting PHP-FPM) treats the same field as a
  URL and strips everything from `?` onward when handing off to FastCGI, so
  the backend executes plain `admin.php` anyway. Two modules, two different
  readings of one field, and the gap between those readings *is* the
  authentication bypass.
- **XSS-to-RCE via handler confusion.** Legacy code (since 1996) will
  reinterpret an unset `r->handler` from `r->content_type` if a response sets
  one. A CRLF-injectable CGI response header (`Content-Type:
  proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/usr/local/lib/php/pearcmd.php`)
  gets read as an internal proxy handler directive, routing the request into
  PHP's `pearcmd.php` (a known RCE-via-argument-injection target once
  reached) — turning what looked like a plain response-header injection into
  full code execution.

## How to spot it

- Any target fronted by Apache httpd doing rewriting/proxying/CGI handoff
  (mod_rewrite + mod_proxy + PHP-FPM/CGI is the common combination) is worth
  testing truncation characters (`%3F` for `?`, also try `%00`/`#`-style
  historical truncators) against rewrite targets and `.htaccess`-protected
  paths specifically, not just generic path-traversal payloads — the payload
  that matters here manipulates which *module* reads which *substring* of
  the path, not the OS filesystem layer.
- If a `<Files>`/`<Location>` ACL exists in front of a proxied backend
  (FastCGI, a reverse-proxied app server), test whether appending an
  extra-query-string-shaped suffix to the protected filename changes whether
  the ACL matches, independent of whether the backend actually receives that
  suffix.
- Response header injection (CRLF in a redirect `Location`, or anywhere
  else a CGI script controls a response header) against an Apache-fronted
  CGI/FastCGI target is worth treating as a potential handler-confusion
  primitive, not just a header-injection/XSS bug on its own.

## Source

Orange Tsai, "Confusion Attacks: Exploiting Hidden Semantic Ambiguity in
Apache HTTP Server" (2024) —
https://blog.orange.tw/posts/2024-08-confusion-attacks-en/

Not yet encountered on a vault box — added from published research ahead of
hitting it live, same instinct that made IIS shortname enumeration valuable
once it was actually needed.
