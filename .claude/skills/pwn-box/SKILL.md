---
name: pwn-box
description: This skill should be used when the user asks to "pwn <target>", "fully compromise <target>", "run the full agent chain on <target>", "autonomously pwn this box", or gives an HTB/CTF/lab target and wants the complete recon-to-writeup pipeline run end-to-end without manual checkpoints between stages.
version: 1.1.0
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
line before dispatching the next one. If a stage reports itself blocked,
set `status: "blocked"`, `blockedReason` (from the stage's own report),
append a `goal_blocked` timeline line, and skip straight to Goal Relay
(step 5) rather than the remaining stages — a relay report on a blocked
goal is still useful, an empty one isn't.

## Orchestration

Run the pipeline via the Agent tool, fully autonomously — do not pause
for user confirmation between stages. Each stage reads its predecessor's
output from `Recon Output/`, so run them strictly in order and let each
finish before starting the next:

1. **Dispatch `connect-agent`** with the target (HTB machine name, OTW
   `<wargame><level>`, or a bare host for a home lab/client engagement).
   Wait for it to write `Recon Output/<target>-connect.md`. If it reports
   blocked (most commonly: the HTB VPN tunnel isn't up, which it cannot
   start itself since that needs an interactive `sudo` password), treat
   this exactly like any other blocked stage — record it and skip
   straight to Goal Relay (step 6).
2. **Dispatch `recon-agent`** with the same target. Wait for it to write
   `Recon Output/<target>-recon.md`.
3. **Dispatch `exploit-agent`** with the same target. It reads the recon
   findings itself — don't re-paste them into its prompt, just confirm
   the target and that recon is done. Wait for
   `Recon Output/<target>-foothold.md`.
4. **Dispatch `privesc-agent`** with the same target. Wait for
   `Recon Output/<target>-privesc.md`.
5. **Dispatch `writeup-agent`** with the same target. Wait for
   `HTB Writeups/<target>.md` (and any new `Tooling and Scripts/` notes).
6. **Dispatch `goal-relay-agent`** with the target, regardless of whether
   the goal finished cleanly or got marked blocked above. Take the
   returned Artifact URL and write it into the goal's `reportUrl` field
   in the registry. Set the goal's final `status` (`done` unless already
   marked `blocked` above) and `finishedAt`, and append a `goal_done` (or
   the already-recorded `goal_blocked`) timeline line.

## When to Stop Early

Only interrupt stages 1-5 if a stage agent explicitly reports it's
blocked (VPN tunnel down, no viable vector found, privesc vectors
exhausted, scope ambiguity discovered mid-chain) — record it per
Registry Bookkeeping above and move straight to relay. A stage reporting
partial success (e.g. foothold gained but as an unstable shell) is not a
reason to stop; pass it forward and let the next stage work with what
exists. Stage 6 (relay) always runs, blocked or not — never skip it.

## Final Report

Once the chain completes (or stops early), report back concisely: what
stage reached, `user.txt`/`root.txt` contents if captured, the writeup's
file path, and the Goal Relay report URL. If a caller (`orchestrate-goals`
or `infinite-worker`) invoked this skill, that summary is for it to relay
onward, not necessarily for a human waiting in this exact turn.
