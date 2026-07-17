# Security Research Vault — Setup Guide

## What this is
A starter Obsidian vault + Claude Code project for security research,
CTF/HTB writeups, and building agent tooling around your workflow.

## Setup steps

1. **Install Obsidian** (free): https://obsidian.md
2. **Open this folder as a vault** in Obsidian: "Open folder as vault" →
   select `security-vault/`
3. **Install Claude Code** (desktop app or CLI):
   https://claude.com/product/claude-code
4. **Point Claude Code at this same folder.** Claude Code auto-reads
   `CLAUDE.md` at the root every session — that's your agent's standing
   instructions, already filled in below as a starting point.

## Folder structure

```
security-vault/
├── CLAUDE.md              ← agent instructions (auto-loaded by Claude Code)
├── HTB Writeups/          ← finished writeups
├── Recon Output/          ← raw nmap/burp/gobuster dumps
├── CVE Watch/             ← CVE research notes
├── CTF Notes/             ← in-progress challenge notes
├── Tooling and Scripts/   ← agent scripts you build
└── Lab Environment/       ← VM inventory, scope docs, network diagrams
```

## First agent to try

Solve any retired HTB box, then in Claude Code (with this folder open):

> "Here's my terminal output from HackTheBox [box name]: [paste].
> Draft a writeup in HTB Writeups/ following the format in CLAUDE.md."

From there, iterate:
> "Now build me a script in Tooling and Scripts/ that takes an nmap XML
> file and summarizes open ports + flags any versions with known CVEs."

## Notes
- Edit `CLAUDE.md` freely as your workflow evolves — it's just a text file.
- Everything here is plain markdown; back it up with git or Obsidian Sync
  if you want it portable across machines (like the GPD setup).
