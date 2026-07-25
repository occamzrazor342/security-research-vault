# PHP `class_exists()` Autoload Side-Channel as an Auth Bypass

Any PHP app with a **custom SPL autoloader** that treats a class *name* as
trusted input for building a file path is vulnerable to a specific
unauthenticated-execution trick, independent of whatever auth/CSRF checks
the app thinks are gating the code that's about to run.

## The mechanism

`class_exists($name)` (and `is_a()`, `instanceof`, `is_subclass_of()`,
`interface_exists()`, `enum_exists()` — anything that triggers
autoloading) defaults to `$autoload = true`. If a function calls
`class_exists($attacker_controlled_string)` as an early sanity/guard check
— e.g. "make sure this class isn't already defined before I define it
myself" — that single call synchronously runs **every registered
autoloader** against the attacker's string, including any custom
autoloader the app itself registered via `spl_autoload_register()`.

If that custom autoloader resolves namespaced-looking class names into
file paths and `include`s/`require`s them (a completely normal thing for a
plugin/module system to do — "load the class file for
`Vendor\modules\<name>\<Class>`"), then passing a crafted namespaced string
into `class_exists()` makes the autoloader `include` an arbitrary file
under its module directory **as a side effect of the existence check
itself** — before the calling function ever reaches whatever auth,
Referrer/CSRF, or session checks it has *later* in its own body. The
include already ran; those checks are dead code from the attacker's
perspective.

## Why this keeps happening

Developers reason about the function's own explicit checks (the `if
(!$authenticated) die();` a few lines down) and don't think of
`class_exists()` as attacker-reachable code — it's typically treated as
inert introspection, not something that resolves to a file execution.
Custom autoloaders make it exactly that, silently.

## How to find it

1. Look for any endpoint that takes a `module`/`class`/`type`-style string
   parameter and eventually calls `class_exists()`, `is_a()`, or similar on
   an (even indirectly) attacker-influenced version of it.
2. Check whether the app registers its own `spl_autoload_register()`
   callback, and whether that callback builds a file path out of the class
   name it's given (namespace-to-directory mapping is the classic tell —
   `str_replace('\\', '/', $class)`-shaped logic).
3. If both are true, try feeding the guard check a namespaced string
   pointing at a *different* module/class than the one the endpoint
   normally dispatches to. Compare the error output/behavior against the
   normal dispatch path — a distinct file path or line number appearing in
   an exception/error message (pointing at the *target* module's file, not
   the dispatcher's own file) is the confirming signal that the include
   fired via the side channel rather than through the normal, gated
   dispatch logic.
4. Once confirmed, the reached file runs with **none** of the checks the
   normal call path would have applied — treat it as a fully unauthenticated
   include of that file's top-level code.

## Fix pattern (what to look for when patch-diffing this class of bug)

A tight allowlist/regex validating the parameter *before* it's ever handed
to `class_exists()` or any autoload-triggering function — specifically one
that rejects the character(s) needed to express a namespace (`\`) or path
traversal (`/`, `..`). Anything less than "reject before first use" is
incomplete, since the include already happens inside the guard check
itself, not in some later, more obviously-dangerous line.

## Seen on
- [[connected]] — [[CVE-2025-57819]]. FreePBX's `admin/ajax.php` used an
  unvalidated `module` GET parameter directly in `class_exists(ucfirst($module))`
  as its first line of `doRequest()`. FreePBX's own registered autoloader
  (`fpbx_framework_autoloader`) recognized `FreePBX\modules\<name>\<file>`-shaped
  class names and `include`d `admin/modules/<name>/<file>.php` accordingly —
  so `module=FreePBX\modules\endpoint\ajax` ran the commercial Endpoint
  Manager module's own `ajax.php` unauthenticated, entirely bypassing the
  Referrer/session checks that `doRequest()` only applies to its *normal*
  dispatch path further down. That reached file then had an unrelated SQLi
  in its own parameter handling, chained into RCE via FreePBX's
  `cron_jobs` table.
