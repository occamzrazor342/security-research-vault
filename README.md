# Security Research

Devin Root's security research practice — penetration testing writeups, published
retired HackTheBox machines, and a couple of standalone tools built along the way.

## Projects

- **[pwnbox-harness](https://github.com/occamzrazor342/pwnbox-harness)** — a
  multi-agent pipeline for Claude Code that runs a security-research engagement
  (recon → exploit → privesc → writeup) end to end, plus the operating discipline —
  16 numbered principles, each tied to a real dated incident — that makes it safe to
  run autonomously against scoped infrastructure. This vault runs on it.
- **[cloud-privesc-graph](https://github.com/occamzrazor342/cloud-privesc-graph)** — a
  vendor-agnostic engine that reads AWS IAM permissions and finds privilege-escalation
  chains through them, even when no single permission looks dangerous on its own.

## Writeups

`HTB Writeups/Machines/` holds full writeups for retired HackTheBox machines — real
recon-to-root walkthroughs with the reasoning behind each step, not just the commands
that worked. Only retired boxes are published here, per HTB's own community guidelines.

## What isn't here

Everything else in this vault (in-progress engagement notes, bug bounty scope/findings,
lab environment details, active/non-retired box work) is private by default and stays
that way — this repo publishes finished, cleared output only, never working notes.
