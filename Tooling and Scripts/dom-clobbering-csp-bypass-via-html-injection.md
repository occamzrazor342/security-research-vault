# DOM Clobbering (CSP-Invisible DOM XSS)

## Why this is a distinct bug class from ordinary DOM XSS

Ordinary DOM XSS needs a sink that executes attacker-controlled *script* —
`innerHTML`, `eval()`, a dynamic `<script src>`. Content-Security-Policy
with a strict `script-src` (no `unsafe-inline`, no `unsafe-eval`) blocks all
of those. **DOM clobbering never executes attacker script at all** — it
abuses the fact that named HTML elements auto-register themselves as global
JS properties, so a page's own trusted JS logic reads an attacker-controlled
*value* out of what it assumes is a safe, developer-defined global. Since
no script tag or inline handler is ever involved, a CSP that would stop
every other injection technique on the same page has nothing to block here.

## The mechanism

Any element with an `id` (or `name`, for a subset of element types) becomes
accessible as `window.<that id>` if no real JS variable of that name already
exists. This is enough on its own to clobber a simple
`if (!window.config) { ... }`-style guard or a bare string/boolean global.
Deeper structures chain multiple elements together:

- **Object property via `<form>`+child:** `x.y` —
  `<form id=x><output id=y>clobbered</output></form>` — `output`/other named
  descendants of a form become named properties on the form element itself.
- **Array-like via duplicate `id`:** giving two elements the same `id`
  makes that global resolve to an `HTMLCollection`, letting `name`
  attributes on the members act like extra indices/keys into it —
  `<a id=x><a id=x name=y href="clobbered">` exposes `x.y`.
- **Three-plus levels via nested `<form>`:**
  `<form id=x name=y><input id=z></form><form id=x></form>` clobbers
  `x.y.z`.
- **Deepest chaining via `<iframe name=...>`:** an iframe's `name`
  attribute assigns the iframe's own `contentWindow` to the global of that
  name, and a `srcdoc`-loaded nested document lets you keep chaining inside
  it — e.g.
  `<iframe name=a srcdoc="<iframe srcdoc='<a id=c name=d href=cid:x>t</a><a id=c>' name=b>">`
  reaches `a.b.c.d` from outside.

## What to look for in target JS

Any code that reads a **global variable it never explicitly assigned** and
uses the result unsafely — a common real pattern is building a script URL,
API base, or config object from `window.someConfigVar.someField` without
checking it's actually the expected type. If an HTML-injection point exists
anywhere earlier in the same document (even one that looks "useless" for
classic XSS because it can't reach a script-executing sink), it may still
be enough to clobber that global before the vulnerable JS runs.

## How to spot it

- Grep target JS bundles for reads of bare globals (`window.X`, bare `X`
  in a non-strict-mode global scope) that get used in a sink (URL
  construction, `href`/`src` assignment, a comparison used for an auth/
  feature-flag decision) without a preceding explicit assignment in the
  same codebase.
- Confirm the injection point actually lands *before* the vulnerable script
  runs in document order — clobbering only affects globals resolved after
  the clobbering elements are parsed.
- Burp's DOM Invader (built into Burp's embedded browser) automates
  detection of clobberable sinks on a live page.

## Source

PortSwigger Research: "DOM Clobbering Strikes Back" and "Bypassing CSP via
DOM Clobbering" — https://portswigger.net/research/dom-clobbering-strikes-back
and https://portswigger.net/research/bypassing-csp-via-dom-clobbering ;
Web Security Academy: https://portswigger.net/web-security/dom-based/dom-clobbering

Not yet encountered on a vault box — added from PortSwigger research ahead
of hitting it live. Worth cross-checking against
[[angularjs-csti-directive-injection-bootstrap]] on any target where a CSP
already ruled out that technique — clobbering is a live option precisely
*because* it doesn't need `unsafe-inline`/`unsafe-eval`.
