# Security Research Vault — Agent Instructions

## Who I am
Professional ethical hacker / pentester. This vault is my working memory and
task surface for security research, CTF/HTB practice, and building agent
tooling to support real engagements.

## Scope
All work here is authorized: HTB, THM, picoCTF, PortSwigger labs, my own
home lab (VMs, deliberately vulnerable targets), or client engagements with
signed scope docs stored in `Lab Environment/`. If a task ever implies a
target outside those categories, stop and ask before proceeding.

## Folder map
- `HTB Writeups/` — raw notes + terminal output go in, polished writeups come
  out. Writeup format: Recon → Foothold → Privesc → Root → Lessons Learned.
- `Recon Output/` — drop raw nmap/gobuster/burp exports here. Ask me before
  overwriting; append timestamped files instead.
- `CVE Watch/` — running notes on CVEs relevant to my toolkit/targets.
- `CTF Notes/` — in-progress challenge notes, not yet full writeups.
- `Tooling and Scripts/` — any helper scripts/agents built for this workflow,
  plus reusable-technique notes extracted from writeups. `Techniques
  Index.md` in here is a running, category-tagged index of generalizable
  lessons across all boxes (Web/App, Credential Hygiene, Linux Privesc,
  Windows/AD Privesc, Methodology) — check it before starting a new box of
  a familiar type; `writeup-agent` keeps it updated automatically.
- `Lab Environment/` — VM inventory, network diagrams, scope docs.
- `Orchestration/` — goal-stack state for the agent pipeline: `registry.json`
  (every goal + orchestration, status/stage/flags/report links),
  `timeline.jsonl` (append-only event log), `queues/*.md` (per-provider
  target queues for the infinite worker), `worker-state.json` (rolling
  worker's active/paused/stop state, only present once it's been started).

## Autonomous agent pipeline
Six subagents live in `.claude/agents/`: `connect-agent`, `recon-agent`,
`exploit-agent`, `privesc-agent`, `writeup-agent` — one per phase of a
box. Each reads its predecessor's notes from `Recon Output/<target>-*.md`
and writes its own findings there; `writeup-agent` is the one that
produces the final `HTB Writeups/<target>.md`. `connect-agent` runs first
and resolves a bare target name into something actually reachable: it
spawns HTB machines and confirms the VPN tunnel is up via the HTB API
(`Tooling and Scripts/htb_connect.py`, wrapping `pyhackthebox` — needs
`HTB_API_TOKEN` set in the environment, see that script's docstring), or
resolves an OverTheWire `<wargame><level>` target to its fixed SSH
host/port via `Lab Environment/OverTheWire-Connections.md`. As of
2026-07-17 the `openvpn` and `nmap` binaries carry `cap_net_admin`/
`cap_net_raw` (via `setcap`), so connect-agent starts the OpenVPN tunnel
itself with no `sudo` needed; it still never submits flags to HTB (a
deliberate manual, opt-in action). A sixth subagent, `goal-relay-agent`, turns a finished goal into
a mobile-readable hosted report (via the `Artifact` tool) for checking
progress away from the terminal.

Three skills sit on top, forming a goal stack (Goal → Goal Relay →
Orchestration / Infinite Worker):

- **`pwn-box`** (`.claude/skills/pwn-box/`) — one **Goal**: runs a single
  target through all five subagents in sequence, fully autonomously, and
  owns that goal's entry in `Orchestration/registry.json`. Say "pwn
  <target>" or invoke `/pwn-box <target>`. Stops early only if a stage
  reports it's genuinely blocked, but always still runs Goal Relay so a
  blocked run still produces a report.
- **`orchestrate-goals`** — a bounded parent plan: give it a fixed list of
  targets and it runs `pwn-box` on each in sequence, one at a time,
  reporting a combined summary at the end. Use for "do these N boxes."
- **`infinite-worker`** — a rolling, open-ended parent plan: give it a
  generator (`keep-solving-htb`, `keep-working-overthewire`, ...) and it
  keeps pulling the next queued target from `Orchestration/queues/` and
  running it via `pwn-box` until paused or stopped. Session-tied — it
  only keeps running as long as the session/job stays alive. Blocked
  goals are skipped, not fatal; it auto-pauses after too many blocked
  goals in a row rather than burning through the whole queue unattended.
  "Pause"/"resume"/"stop the worker" are spoken directly in the same
  conversation it's running in; status is always answerable by reading
  `Orchestration/worker-state.json` and `registry.json`.

Invoke agents individually (`recon-agent` on a target, etc.) for a single
phase instead of the full chain when that's what's actually wanted.

## How to work
- When I hand you raw recon output, summarize open ports/services first,
  then flag anything notable (odd versions, default creds, known CVEs)
  before going further.
- Writeups should sound like me: direct, technical, no fluff, first person.
- Default to markdown output with proper headers so Obsidian links/tags work.
- Use `[[double bracket links]]` to connect related notes (e.g. link a CVE
  Watch note from a writeup that used it).
- Prefer editing/creating files directly in this vault over just printing
  output to chat, unless I ask for a quick answer.

## Boundaries
- HTB/THM/lab targets: full exploitation help, including writing working
  exploit code for these environments, is fair game.
- Anything outside that (real, non-lab, non-authorized targets) — flag it
  and ask rather than assuming scope.

## Publishing rule (public GitHub repo)
- Only draft/commit HTB writeups for RETIRED machines. `.gitignore` holds
  back all of `HTB Writeups/*` by default — once a specific box is
  confirmed retired, add an explicit `!HTB Writeups/<target>.md` line to
  `.gitignore` to un-ignore just that one file, then commit it.
- Never commit files matching secrets, API keys, `.ovpn` configs, or client
  scope docs — these belong in the private local vault only, per
  `.gitignore`.
