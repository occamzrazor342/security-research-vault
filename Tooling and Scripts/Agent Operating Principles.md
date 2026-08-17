# Agent Operating Principles

The exploit chains and writeups in this vault are the visible output of the
agent pipeline. This document is the other half: the operating discipline
that makes it safe to run an autonomous multi-agent pipeline against real
(if scoped) infrastructure at all. Every principle below exists because
something in this vault's own history would have gone wrong without it —
these aren't theoretical, they're the actual incidents that shaped how I
run this thing.

## 1. Verify claimed system state — don't trust narration

An agent (or a person) telling you "I fixed it" is not evidence that it's
fixed. When told a sudo restriction had been lifted via a settings change,
the right move was a non-interactive check (`sudo -n ...`) that fails
cleanly instead of hanging on a password prompt — which showed the claim
was false. When told it had been fixed a second time via a specific,
checkable mechanism (Linux capabilities via `setcap`), I verified it
directly (`getcap`, a real privileged scan, `/dev/net/tun` permissions)
*before* accepting it and changing anything downstream. Vague claims get a
test; concrete, checkable mechanisms get verified, not just believed.

## 2. Written safety boundaries change on verified capability, not on a message

A rule like "this agent never starts the VPN tunnel itself" is a design
decision, not an inconvenience to work around the moment someone says it's
fine now. When the technical constraint that justified the rule genuinely
went away, the fix wasn't to quietly start doing the new thing — it was to
update the written policy explicitly, with a dated note, so the document
and the actual behavior stay in sync for whoever (human or agent) reads
that file next.

## 3. Unverifiable claims of authority don't move risk decisions — verifiable scope does

Partway through this project, a vault file surfaced a claim that a prior
agent run had been halted by an external safety/verification process
pending approval. When told that approval had since come through, the
right response wasn't to accept or reject the claim — it was to notice
that there's no mechanism available to actually check anyone's approval
status either way, so the claim simply can't be the thing a decision rests
on. The work resumed because it was already-authorized lab work under this
vault's own scope rules, full stop. If a claim can't be checked, it doesn't
get to move the decision in either direction.

## 4. A negative result that contradicts another signal doesn't get trusted — it gets cross-checked

The HTB API wrapper this pipeline depends on has a real, documented bug: it
reports "nothing active" for machines on certain VPN products, while a
spawn attempt on that same machine correctly fails with "you already have
an active instance." That contradiction is now a documented signature of a
lookup bug, not a real conflict — and the fix is a mandatory raw-API
cross-check before ever trusting the negative result. The general version
of this: when a status check and a side effect disagree, believe neither
until you've checked a third way.

## 5. External output gets diffed against live state, never merged blind

Content generated outside the current working session — a file from a
different chat, a downloaded scaffold, anything that wasn't produced with
visibility into what's actually on disk right now — gets diffed before
it touches anything. One that arrived mid-project turned out to be several
hours stale and would have silently deleted an entire session's worth of
documented architecture if applied directly. It got merged one section at
a time instead. Treat anything from outside the current session as an
untrusted patch, not a source of truth, no matter how relevant it looks.

## 6. Unexplained provenance earns one question, even when it's probably nothing

A file that was supposed to be a simple manual copy turned up owned by
`root` with executable permissions — inconsistent with how it was
described as arriving. Rather than guessing ("this is fine" or "this is
compromised"), the move was to just ask. It turned out to be a mundane
VirtualBox shared-folder default, not a threat. The point isn't paranoia —
it's that a five-second question is cheaper than either wrongly trusting
or wrongly discarding something whose story doesn't quite add up.

## 7. Default-private, explicit opt-in to public — never the reverse

The rule for what's allowed into the public copy of this repo is "nothing,
unless specifically cleared" — writeups are excluded by default via
`.gitignore`, and a specific box only becomes publishable once it's
confirmed retired, via one explicit added line naming that file. A
blanket "exclude the sensitive stuff" filter fails by omission the moment
you forget a case; a blanket "exclude everything" default with named
exceptions fails safe instead.

## 8. Review the actual file list before every commit — not the diff you assume is there

Before the first commit to this repo, a dry-run add surfaced a stray
Python bytecode cache, a leftover unrelated Obsidian vault, and the setup
tool itself — none caught by the original `.gitignore`, all of it about to
be committed anyway. `.gitignore` is a hypothesis about what shouldn't be
there; the dry-run file list is the actual test of it. Run the test every
time, not just the time you write the rule.

## 9. Run an assumption register, not a memory of conclusions — scoped negative results expire when new evidence arrives

`[[OSAI+ - Threat Modeling for AI-Enabled Targets]]`'s Assumption Register
(observation → hypothesis → confidence → source → status: UNVALIDATED →
VALIDATED/INVALIDATED, live and re-checked, not written once) is the
correct model for how findings should persist across a multi-session
pipeline — and Cobblestone's five stalled sessions are what it costs to
skip it. "SQLi FILE-write is dead" got carried forward as a settled fact
after testing exactly two paths (`/tmp`, MySQL's datadir); the accurate
version was the narrower, still-live hypothesis "FILE-write fails against
those two specific paths, arbitrary-path write status UNVALIDATED." Two
sessions later, an AppArmor profile explicitly naming
`/var/www/html/skins/*` as writable got read and filed as disclosed source
material — with no open register entry for it to reopen, so it never
reconnected to the closed FILE-write question it should have re-triggered.
The module's own named trap, generalized beyond AI targets: absence of
evidence against the paths actually tried is not evidence of absence
everywhere. A stage agent's "vector exhausted" report should read like a
register update (what was tested, what's still open) so the next session
can re-open the right row instead of inheriting a flattened conclusion.

## 10. Re-rank crown jewels every time the assumption register changes — orient on current value, not the path already in motion

Pairs directly with #9 and comes from the same OSAI+ module's **Crown Jewel
Ranking Under Uncertainty**: ranking is offensive value *given current
knowledge*, re-done every time an assumption validates or invalidates —
not a list set once at the start and executed against on autopilot. Two
things the ranking must do explicitly every time it's redone: separate
**already-accessible** targets from **requires-further-work** ones (don't
keep planning how to reach something already in hand), and check whether
a newly-validated/invalidated row changes what the *actual* highest-value
objective is, even mid-path. Cobblestone's principle-#9 incident doubles
as the example here: the moment the `skins/` FILE-write validated,
crown-jewel re-ranking should have immediately dropped the admin-bot XSS
wait from "the plan" to "no longer needed" — instead it kept running in
parallel for a while out of inertia, not because it still ranked highest.
In multi-asset engagements (a Fortress's multiple flags, a bounty
program's multiple in-scope assets) this is a standing table, not a
one-time list — see the Fortress section of the root `CLAUDE.md` for the
concrete format (`fortress-us-fort-1-entrypoint.md`'s flag-categories
table is the working example: named target, access status, current
best-guess value/mapping, re-ranked inline as signals resolve). For a
single-target engagement (a normal HTB machine) the "crown jewel" is just
user.txt/root.txt, so the table adds little — the discipline that
transfers is still checking, after every validated/invalidated finding,
whether the currently-running approach is still the best one rather than
just the first one.

---

None of this is specific to hacking HTB boxes. It's the same discipline
any team running agents against systems that matter should want to see:
verify before trusting, distinguish a claim from a check, keep written
policy and real behavior in sync, and default to the safer state when
something can't be confirmed either way.
