---
name: pwn-box
description: This skill should be used when the user asks to "pwn <target>", "fully compromise <target>", "run the full agent chain on <target>", "autonomously pwn this box", or gives an HTB/CTF/lab target and wants the complete recon-to-writeup pipeline run end-to-end without manual checkpoints between stages.
version: 1.2.0
---

# pwn-box — Autonomous Recon-to-Writeup Pipeline

## Scope Gate

Before doing anything else, confirm the target falls within this vault's
authorized scope per the root `CLAUDE.md`: HTB, THM, picoCTF, PortSwigger
labs, a home lab, or a client engagement with a signed scope doc in
`Lab Environment/`. If the target is ambiguous or clearly outside that
scope, stop and ask before dispatching any agent.

## Registry Bookkeeping

`Orchestration/registry.json` tracks every goal (a goal = one target run
through this pipeline). This skill owns updating it — the stage agents
don't touch it themselves.

Before dispatching `connect-agent`, find or create this goal's entry in the
`goals` array of `Orchestration/registry.json` (id: `<target-slug>-<date>`,
e.g. `makesense-2026-07-16`; if an orchestrator — `orchestrate-goals` or
`infinite-worker` — already created the entry, reuse it rather than
duplicating). Set `status: "running"`, `stage: "connect"`, `startedAt`.
Append a `{"at","type":"goal_started","goalId","detail":"<target>"}` line
to `Orchestration/timeline.jsonl`.

After each stage completes, update the goal's `stage` field and append a
`{"at","type":"stage_done","goalId","detail":"<stage name>"}` timeline
line before dispatching the next one. **Not every "blocked" report from a
stage ends the goal** — see "Handling a Blocked Stage" below for the
distinction. Only when that section says to actually stop do you set
`status: "blocked"`, `blockedReason` (from the stage's own report), append
a `goal_blocked` timeline line, and skip straight to Goal Relay (step 6)
rather than the remaining stages — a relay report on a blocked goal is
still useful, an empty one isn't.

Track `reconEscalations` (integer, default 0) on the goal's registry
entry — how many extra recon-agent passes this specific pwn-box run has
spent trying to unstick a blocked exploit/privesc stage (see below). This
is uncapped — it's a record of effort spent, not a budget being counted
down against — so keep incrementing it across as many passes as it takes.
Reset it to 0 at the start of a fresh pwn-box invocation for a goal, even
if that goal was previously blocked and is now being resumed.

## Orchestration

Run the pipeline via the Agent tool, fully autonomously — do not pause
for user confirmation between stages. Each stage reads its predecessor's
output from `Recon Output/Machines/`, so run them strictly in order and let each
finish before starting the next:

1. **Dispatch `connect-agent`** with the target (HTB machine name, OTW
   `<wargame><level>`, or a bare host for a home lab/client engagement).
   Wait for it to write `Recon Output/Machines/<target>-connect.md`. If it reports
   blocked (most commonly: the HTB VPN tunnel isn't up, which it cannot
   start itself since that needs an interactive `sudo` password), this is
   a real hard stop (see below) — record it and skip straight to Goal
   Relay (step 6).
2. **Dispatch `recon-agent`** with the same target. Wait for it to write
   `Recon Output/Machines/<target>-recon.md`.
3. **Dispatch `exploit-agent`** with the same target. It reads the recon
   findings itself — don't re-paste them into its prompt, just confirm
   the target and that recon is done. Wait for
   `Recon Output/Machines/<target>-foothold.md`. If it reports no viable vector
   found, this is a soft block — apply the Recon-Escalation Retry Loop
   below before treating it as a hard stop.
4. **Dispatch `privesc-agent`** with the same target. Wait for
   `Recon Output/Machines/<target>-privesc.md`. Same handling: a "vectors
   exhausted" report is a soft block, not an automatic hard stop — apply
   the retry loop below.
5. **Dispatch `writeup-agent`** with the same target. Wait for
   `HTB Writeups/Machines/<target>.md` (and any new `Tooling and Scripts/` notes).
6. **Dispatch `goal-relay-agent`** with the target, regardless of whether
   the goal finished cleanly or got marked blocked above. Take the
   returned Artifact URL and write it into the goal's `reportUrl` field
   in the registry. Set the goal's final `status` (`done` unless already
   marked `blocked` above) and `finishedAt`, and append a `goal_done` (or
   the already-recorded `goal_blocked`) timeline line.

## Handling a Blocked Stage

**HTB/lab targets are exploitable by design.** A stage reporting "no
viable vector" is a statement about what *this pass's* recon surfaced,
not a verdict that the target is unsolvable — treat it as a prompt to dig
deeper, not as a reason to give up. There is no cap on how many
recon-escalation passes this can take — keep looping until it lands. The
only things that should actually end a goal early are the hard stops
below: a genuine environment fact no amount of digging fixes, or actually
running out of session budget (a real usage-limit cutoff hit while
working the loop, not a self-imposed pass count).

**Hard stops — record and skip straight to Goal Relay, no retry loop:**
- `connect-agent` blocked (VPN/tunnel/spawn failure, missing `sudo` for
  something it can't work around). This is an infrastructure fact about
  *this session*, not about the target — more recon can't fix a network
  that isn't up.
- Scope ambiguity discovered at any stage.
- A stage hits a genuine session/resource ceiling it cannot work around
  (Anthropic usage-limit cutoff, a sandbox capability that's actually
  missing, a safety-classifier block on the instance — per this vault's
  own operating principles, verify these rather than accepting narration
  at face value before treating them as hard stops).

**Soft blocks — `exploit-agent` or `privesc-agent` reports no viable
vector from the current recon:** apply this loop instead of stopping:

1. Read the blocked stage's own report for its concrete recommendations
   (specific unresolved hosts/services/attributes/gaps — every
   well-formed blocked report from these agents names some). If it
   genuinely names nothing concrete, that itself is worth noting, but
   don't invent gaps to search for.
2. Dispatch `recon-agent` again for the same target, with the `model`
   parameter overridden to the full/inherited tier (per recon-agent's own
   "Note on model tier" — a vector-exhausted outcome is exactly its
   documented trigger for this override), and a prompt built from the
   blocked stage's concrete gaps rather than a generic "look harder."
   Instruct it to append a new dated section to the existing
   `<target>-recon.md` rather than overwriting prior findings. Increment
   `reconEscalations` by 1.
3. Re-dispatch the same stage that was blocked (`exploit-agent` or
   `privesc-agent`), instructing it to read the new recon section first
   and pick up from there rather than re-trying vectors already
   documented as exhausted in its own prior report.
4. If it lands (foothold/escalation achieved), continue the pipeline
   normally from there. If it blocks again, go back to step 1 — each
   pass should be looking for something the previous pass didn't have,
   not repeating the same search. Keep looping for as many passes as it
   takes; only stop if a pass itself hits one of the hard stops above
   (e.g. a real usage-limit cutoff reached mid-loop).

A stage reporting partial success (e.g. foothold gained but as an
unstable shell) is never a reason to stop — pass it forward and let the
next stage work with what exists. Stage 6 (relay) always runs, blocked or
not — never skip it.

## Final Report

Once the chain completes (or stops early), report back concisely: what
stage reached, `user.txt`/`root.txt` contents if captured, the writeup's
file path, and the Goal Relay report URL. If a caller (`orchestrate-goals`
or `infinite-worker`) invoked this skill, that summary is for it to relay
onward, not necessarily for a human waiting in this exact turn.
