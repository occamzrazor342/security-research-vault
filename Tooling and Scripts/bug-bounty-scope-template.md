# <Program Name> — Scope

Copy this file to `Bug Bounty - <Program Name>/scope.md` when starting a new
program. `scope-agent` reads this, cross-checks it against the live platform
page, and produces `scope-resolved.md` in the same folder — that resolved
file, not this one, is what every downstream bounty agent actually acts on.

## Program Identity

- **Platform:** HackerOne
- **Program name:**
- **Program URL:** (the actual live policy page — `scope-agent` will re-fetch
  this every time it runs, so keep it accurate)
- **Account/handle used:**
- **Snapshot date:** (when this file was last verified against the live page)

## In-Scope Assets

List exactly as the program defines them — domains, IP ranges, mobile apps,
API endpoints, wildcards. If the program's own scope table has a severity/
bounty-eligibility column per asset, keep it here too.

-

## Out-of-Scope / Excluded

Explicit exclusions the program calls out (third-party integrations, staging
environments unless stated otherwise, specific endpoints, specific
vulnerability classes like clickjacking/self-XSS/rate-limiting-only reports,
etc.):

-

## Allowed Testing Types

-

## Prohibited Techniques

Quote the program's own wording where it matters (e.g. "no automated
scanners without prior approval," "no denial-of-service testing," "no social
engineering," "no testing against production data belonging to other
users"):

-

## Rate Limits / Testing Windows

-

## Data Handling Rules

What the program says about handling any data you might incidentally access
(e.g. "stop immediately and report, do not download/store"):

-

## Disclosure Policy

- Disclosure timeline / embargo terms:
- Safe harbor statement (quote verbatim if the program has one):

## Special Program Notes

Anything else specific to this program that doesn't fit the categories above
— known quirks, contact preferences, prior communication with the triage
team, etc.

-
