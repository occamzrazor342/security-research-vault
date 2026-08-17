# AngularJS CSTI via directive-attribute injection into an `ng-app` bootstrap subtree

## The pattern

Angular 1.x compiles a page in two structurally different ways, and only one
of them is what most people mean when they say "Angular is loaded on this
page":

1. **Post-bootstrap DOM insertion** (`innerHTML`, `ng-bind-html`,
   `$sce.trustAsHtml()`, jQuery `.html()`, etc.) — content injected into the
   live DOM *after* Angular's initial `$compile` pass never gets compiled.
   Directives (`ng-click`, `ng-focus`, `{{ }}` interpolation) inside it are
   inert, plain markup. This is the sink most people test for CSTI and,
   correctly, find nothing.
2. **Initial-page-load bootstrap** — when Angular auto-bootstraps off an
   `ng-app` attribute (or `angular.bootstrap()` is called explicitly), it
   runs `$compile` over the **entire DOM subtree already present** under
   that root element at the moment bootstrap runs. This scan is
   attribute/tag-name-driven, not sink-driven — it doesn't matter whether
   the specific element was a "known" directive target before that moment;
   Angular discovers directives by literally walking every attribute in the
   subtree. If server-rendered, stored/reflected HTML sits inside an
   `ng-app` root **and is already part of the response body Angular
   bootstraps against** (not injected client-side afterward), any directive
   attribute in it — `ng-click`, `ng-focus`, `ng-mouseover`, `ng-init`,
   etc. — gets wired up exactly like a directive the developer wrote by
   hand.

The two are easy to conflate. "There's no `ng-bind-html` on this element, so
Angular never touches it" is **wrong** the moment that element is inside an
`ng-app` root and present at initial page load — the compiler doesn't care
that nobody explicitly marked it as a directive site.

## Why this beats a strict CSP

A native inline event-handler attribute (`onload=`, `onclick=`, `onerror=`)
is blocked outright by any CSP without `unsafe-inline` in `script-src` — the
browser itself refuses to execute it, full stop, regardless of what markup
sanitization missed. `ng-focus="..."`/`ng-click="..."` are **not** native
HTML attributes at all — they're inert custom attributes as far as the
browser/CSP is concerned. Angular's own already-loaded, `'self'`-origin
script reads them and wires up a normal `addEventListener` call under the
hood. CSP has no visibility into that — it only governs where *script
sources* come from and blocks native inline-handler execution, neither of
which this path touches. A strict `script-src 'self'` (no `unsafe-inline`,
no `unsafe-eval`) policy is fully consistent with this technique working.

Pairing the directive with a native `autofocus` attribute removes the need
for any user interaction: `autofocus` fires the browser's native `focus`
event automatically on page load, which `ng-focus` is listening for, so the
Angular expression fires with zero clicks.

## Minimal payload shape

```html
<p ng-focus="formData.comment=$event.view.document.cookie;submitForm()" autofocus tabindex="0">
  Loading article content...
</p>
```

`tabindex="0"` isn't strictly required by every browser/Angular version but
makes the element reliably focusable. The specific expression
(`formData.X=...;someScopeFunction()`) has to reference **real scope members
of the actual controller** bound to the `ng-app`/`ng-controller` pair that
wraps the injection point — read the app's own controller JS first (not a
generic payload) to find a scope property/function that does something
useful (submits a form, POSTs somewhere, navigates) rather than guessing.

## How to confirm this applies before spending payload-crafting effort

1. Confirm Angular core is loaded (`angular-*.min.js` in the response) —
   necessary but not sufficient.
2. Find the actual injection point and check whether it sits **inside** an
   `ng-app="..."` (or `ng-controller="..."`) element **and** is part of the
   raw HTML already present in the HTTP response body — not something
   inserted by a later AJAX call/`innerHTML` write. `curl` the page
   unauthenticated/pre-JS and grep for the injection point relative to the
   `ng-app` boundary; don't rely on browser dev tools, which show the
   post-render DOM and won't distinguish "was here at load" from "inserted
   later."
3. Pull every custom (non-vendor) JS file the app serves and read the real
   controller(s) bound to that `ng-app` root for scope members/functions
   worth invoking (a comment-submit handler, a navigation call, anything
   that does something observable).
4. Don't assume a specific named CVE (e.g. an `ngSanitize`/`$sanitize`
   bypass CVE) is the mechanism just because AngularJS is in play and a
   payload from a writeup happens to work — check whether the vulnerable
   *module* (`ngSanitize`, specifically) is even loaded at all before
   citing it. This exact confusion is documented in
   [[Eloquia#Foothold|Eloquia's own writeup]]: the working payload class on
   that box is this bootstrap-subtree CSTI technique, not the specific CVE a
   third-party reference cited for it.

## Distinct from the classic AngularJS sandbox-escape CSTI

The well-known `{{constructor.constructor('alert(1)')()}}`-style AngularJS
CSTI (interpolation-expression sandbox escape, pre-1.6) needs `eval()`/
`Function()`, which a strict `script-src` CSP with no `unsafe-eval` blocks
outright even if the sandbox escape itself succeeds. This directive-
attribute technique doesn't evaluate arbitrary JS via `Function()` at
all — it calls a real, already-defined scope function through Angular's
normal event-binding machinery, so it isn't affected by that CSP directive
either. Treat these as two separate technique families with different CSP
exposure, not variants of the same attack.

See also [[Eloquia]] for the full box this was discovered/weaponized on.
