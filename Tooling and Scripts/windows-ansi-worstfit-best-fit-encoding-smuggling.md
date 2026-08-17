# Windows ANSI "Best-Fit" Character Smuggling (WorstFit)

## Why this is a distinct bug class

Windows keeps legacy ANSI code pages around for backward compatibility even
though everything internally is UTF-16. Any time a UTF-16 string crosses into
an ANSI API (`*A`-suffixed Win32 calls, many CGI/legacy-interop code paths),
the OS has to downgrade it — and for a Unicode character with no exact match
in the target code page, it doesn't fail or drop the character, it silently
substitutes a **visually/semantically "close enough" ANSI character**
instead ("best-fit" conversion). That substitution happens *after* any
application-layer validation/escaping has already run and approved the
original Unicode string, so it's an encoding-layer smuggling primitive that
sits underneath the application entirely — structurally similar to how
[[http-desync-client-side-connection-reuse]] smuggles bytes underneath an
application's request parsing, just at the OS charset-conversion layer
instead of the TCP layer.

## Three concrete techniques (Orange Tsai, "WorstFit", 2025)

- **Filename smuggling.** Fullwidth slash/backslash lookalikes and certain
  currency symbols (e.g. ¥, ₩) best-fit-map to real `/`/`\` path separators
  in several code pages. An app that validates a Unicode filename (correctly
  rejecting real slashes) before an ANSI file API silently converts it can
  still get path traversal — the string that got validated and the string
  that gets used as a path are not the same string.
- **Argument splitting.** A fullwidth quotation mark (U+FF02) best-fit-maps to
  a plain ASCII `"` before subprocess argument parsing. An application that
  correctly escapes real `"` characters in user input before building a
  command line can still have its escaping bypassed, because the quote that
  reaches the shell/argument parser wasn't in the string when the escaping
  ran.
- **Environment-variable / CGI confusion.** The same best-fit substitution
  applied to CGI variables or other ANSI-retrieved environment strings lets
  an attacker swap in a Unicode lookalike for a character a WAF/filter
  blocks, recovering the blocked character only after the filter has already
  passed the string through.
- **CVE-2024-4577 (PHP-CGI)** is the concrete, live instance: PHP-CGI had
  already patched argument injection via a literal `?-s` query string over a
  decade ago. The soft hyphen (U+00AD) best-fit-maps to a plain `-` on
  Japanese/Simplified-Chinese/Traditional-Chinese Windows code pages, so
  `?%ADs` sails past the old patch's literal-`-` check and reintroduces the
  exact same argument-injection primitive (source disclosure or RCE) the
  2012-era fix believed it had closed for good.

## How to spot it

- Any Windows-hosted service that does its own input validation/escaping in
  application code and *then* calls into a legacy ANSI-suffixed API,
  subprocess spawn, or CGI-style variable read is a candidate — the
  vulnerable gap is specifically between "validated as Unicode" and "consumed
  as ANSI."
- Non-English (esp. CJK) code pages are where the richest set of best-fit
  collisions exist — a target explicitly configured with a Chinese/Japanese/
  Korean system locale is measurably higher-value to test this against than
  an English-locale box, since more visually-unrelated Unicode characters
  best-fit-collapse onto meaningful ASCII characters in those code pages.
- Treat "we already patched a literal-character injection bug years ago" as
  no guarantee against this class — CVE-2024-4577 shows the exact same old
  primitive reachable again through an encoding-equivalent character the
  original fix never accounted for.

## Source

Orange Tsai, "WorstFit: Unveiling Hidden Transformers in Windows ANSI!"
(2025) —
https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/

Not yet encountered on a vault box — added from published research ahead of
hitting it live, same instinct that made IIS shortname enumeration valuable
once it was actually needed.
