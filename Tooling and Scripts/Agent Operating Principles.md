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

---

None of this is specific to hacking HTB boxes. It's the same discipline
any team running agents against systems that matter should want to see:
verify before trusting, distinguish a claim from a check, keep written
policy and real behavior in sync, and default to the safer state when
something can't be confirmed either way.
