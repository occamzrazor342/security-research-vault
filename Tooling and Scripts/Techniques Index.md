# Techniques Index

Cross-box patterns worth knowing *before* starting a similar box, not just
after finishing one. Each entry is a one-line generalization with a link
back to the box's own Lessons Learned section for full context — this file
is a pattern-matching aid, not a replacement for the writeup.

**How this gets maintained:** `writeup-agent` appends to this file as the
last step after drafting each box's Lessons Learned section. It only adds
entries that generalize beyond the specific box (skip box-specific trivia);
it reuses an existing category header if one fits, and creates a new one
if none does.

## Web / Application

- NoSQL/aggregation-pipeline injection: a stage denylist that only checks
  *top-level* stage names can often be bypassed by nesting the blocked
  stage (e.g. `$lookup`) inside an allowed one (e.g. `$facet`). Worth
  testing on any app that exposes a raw pipeline/query parameter, not just
  MongoDB specifically.
- Client-side "encryption" with the key shipped in the JS bundle isn't
  encryption — it's obfuscation, and just as forgeable as no encryption.
  — [[MakeSense#Lessons Learned|MakeSense]]
- Any feature that turns user-controlled input into raw HTML/JS
  metacharacters before persisting it needs output escaping on render,
  regardless of how unlikely the input channel (voice, OCR, etc.) seems.
  — [[MakeSense#Lessons Learned|MakeSense]]
- Stored XSS on any page an admin will view is a straight line to full
  compromise — no credential theft needed, just ride the admin session.
  — [[MakeSense#Lessons Learned|MakeSense]]

## Credential & Secret Hygiene

- Commented-out / disabled config blocks are not dead credentials —
  nobody rotates a password just because the code path referencing it is
  "off." Treat every credential found in a config file as live until
  proven otherwise. — [[kobold#Lessons Learned|kobold]]
- Credential reuse across technically unrelated apps is still the
  highest-yield privesc technique available, even on boxes stacked with
  real CVEs — check it before diving deep into version-specific exploits.
  — [[kobold#Lessons Learned|kobold]]
- One leaked credential reused across multiple tiers (DB password = system
  password = internal-app Basic Auth password) can compromise everything
  above and below it at once — always test a found credential everywhere,
  not just where it was found. — [[MakeSense#Lessons Learned|MakeSense]]

## Linux Privesc

- Admin access on any container-management platform (Docker API, Arcane,
  Portainer, etc.) is root, full stop, the moment privileged-container
  creation with arbitrary bind mounts is available — that access *is* the
  escalation, don't go looking for a separate "real" bug on top of it.
  Generalized in [[docker-management-api-privesc]].
  — [[kobold#Lessons Learned|kobold]]
- World-writable directories inside a bind-mounted app data volume are a
  bigger exposure than the parent directory's group ACL suggests — check
  actual permissions on subdirectories, not just the mount point.
  — [[kobold#Lessons Learned|kobold]]
- "Localhost-only" (a service bound to 127.0.0.1) is not a security
  boundary once there's any foothold on the box — root-owned local
  services are still attack surface for privesc.
  — [[MakeSense#Lessons Learned|MakeSense]]
- Never trust file-conversion/extraction output (OCR, transcoding, etc.)
  enough to let it write verbatim to a web-servable path with an
  attacker-chosen extension — that's arbitrary file write wearing a
  convenience feature as a costume. — [[MakeSense#Lessons Learned|MakeSense]]

## Windows / AD Privesc

*(no entries yet — first Windows/AD box lessons land here)*

## Methodology

- A strong-looking lead still needs empirical verification, not just
  theoretical applicability — "looks exploitable in code" and "is
  exploitable in this deployment" are different claims. Verify both,
  ideally via real patch-diff analysis rather than taking an advisory on
  faith. — [[kobold#Lessons Learned|kobold]]
- Group/role membership that looks like the obvious intended path can be
  a red herring — don't over-invest in the most visually appealing lead
  before ruling out cheaper ones. — [[kobold#Lessons Learned|kobold]]
- A vector written off during recon is worth re-checking once more context
  exists later in the chain — an assumption made early (e.g. "this route
  404s") can be wrong, and re-testing costs little.
  — [[kobold#Lessons Learned|kobold]]
