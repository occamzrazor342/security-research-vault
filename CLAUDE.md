# Security Research Vault — Agent Instructions

## Who I am
Professional ethical hacker / pentester. This vault is my working memory and
task surface for security research, CTF/HTB practice, and building agent
tooling to support real engagements.

## Scope
All work here is authorized: HTB, THM, picoCTF, PortSwigger labs, my own
home lab (VMs, deliberately vulnerable targets), client engagements with
signed scope docs stored in `Lab Environment/`, or bug bounty programs with
a scope doc stored in their own `Bug Bounty - <Program Name>/` folder (see
"Bug bounty pipeline" below). If a task ever implies a target outside those
categories, stop and ask before proceeding.

## Folder map
- `HTB Writeups/` and `Recon Output/` — both are subfoldered by content type,
  the same four categories in each, so raw notes and their polished writeup
  always live at a matching path:
  - `Machines/` — regular HTB (and OverTheWire) machines. Raw notes +
    terminal output go into `Recon Output/Machines/`, polished writeups come
    out into `HTB Writeups/Machines/`. Writeup format: Recon → Foothold →
    Privesc → Root → Lessons Learned.
  - `Sherlocks/` — DFIR/forensics challenges. Working notes/evidence in
    `Recon Output/Sherlocks/` (`<name>-sherlock.md`, `<name>-evidence/`),
    polished writeups in `HTB Writeups/Sherlocks/` — same retired-only
    publishing rule as Machines but a different internal structure
    (Scenario → task-by-task walkthrough, no Foothold/Privesc/Root since
    there's no shell involved); see "Sherlocks pipeline" below.
  - `Fortresses/` — HTB's multi-host/multi-flag Fortress content. Working
    notes in `Recon Output/Fortresses/`, polished writeups in
    `HTB Writeups/Fortresses/`. No dedicated pipeline/agent yet — sessions so
    far reuse `recon-agent`/`exploit-agent`/`privesc-agent` ad hoc against a
    single running `<name>-entrypoint.md` notes file per Fortress instance.
    Multi-session Fortress engagements have a real failure mode: a session
    scoped narrowly to one lead won't surface a detail outside its own scope,
    so a genuine clue (a literal page title, an odd string) can sit
    unexamined for many sessions in a row. Mitigate this with a standing
    **"Unresolved Signals"** table near the top of the notes file — log any
    oddly-specific detail there the moment it's noticed even if out of the
    current session's scope, mark it investigated/not, and read that table
    (not just the prior session's own "recommended next steps") before
    deciding what to dispatch next. Pair it with a **"Crown Jewels"**
    table — one row per named objective (flag category, high-value host,
    etc.), columns for access status (**already-accessible** vs.
    **requires-further-work**, kept explicitly separate) and current
    best-guess offensive value/mapping — and re-rank it, not just append
    to it, every time a row in Unresolved Signals gets marked
    investigated/resolved: a newly validated or invalidated signal can
    change which objective is actually highest-value right now, even for
    a lead that's mid-flight. `fortress-us-fort-1-entrypoint.md`'s
    "Official flag categories" table is the working example of this
    pattern (started before it had this name). See Agent Operating
    Principles #9–10 for why both tables exist and how they're meant to
    drive each other. Copy the format from
    `Recon Output/Fortresses/fortress-us-fort-1-entrypoint.md` for the next
    Fortress.
  - `Challenges/` — standalone HTB Challenges (short, single-flag Web/Pwn/
    Crypto/etc. puzzles, no OS/privesc chain). In-progress working notes for
    these actually live in `CTF Notes/` (see below) rather than
    `Recon Output/Challenges/` — that subfolder exists for structural parity
    but `CTF Notes/` is the real home for challenge-in-progress material.
    Polished writeups, if ever drafted, go in `HTB Writeups/Challenges/`.

  Drop raw nmap/gobuster/burp exports into the matching `Recon Output/`
  subfolder. Ask me before overwriting; append timestamped files instead.
- `CVE Watch/` — running notes on CVEs relevant to my toolkit/targets.
- `CTF Notes/` — in-progress notes for standalone HTB Challenges (and other
  non-HTB CTF platforms), not yet full writeups. One subfolder per
  challenge.
- `Tooling and Scripts/` — any helper scripts/agents built for this workflow,
  plus reusable-technique notes extracted from writeups. `Techniques
  Index.md` in here is a running, category-tagged index of generalizable
  lessons across all boxes (Web/App, Credential Hygiene, Linux Privesc,
  Windows/AD Privesc, Methodology) — check it before starting a new box of
  a familiar type; `writeup-agent` keeps it updated automatically.
  `Agent Operating Principles.md` documents the operating
  discipline behind this pipeline (verification habits, boundary changes,
  publishing defaults) — read it before changing how any agent is allowed
  to act autonomously.
- `Lab Environment/` — VM inventory, network diagrams, scope docs.
- `Bug Bounty - <Program Name>/` — one self-contained folder per bug bounty
  program (e.g. `Bug Bounty - Acme Corp/`), never a shared `Bug Bounty/`
  umbrella — programs are kept separate on purpose so scope/findings from
  one never bleed into another. Each contains `scope.md` (copied from
  `Tooling and Scripts/bug-bounty-scope-template.md`), `scope-resolved.md`
  (written by `scope-agent`), `Findings/`, and `Reports/`. See "Bug bounty
  pipeline" below.
- `Orchestration/` — goal-stack state for the agent pipeline: `registry.json`
  (every goal + orchestration, status/stage/flags/report links),
  `timeline.jsonl` (append-only event log), `queues/*.md` (per-provider
  target queues for the infinite worker), `worker-state.json` (rolling
  worker's active/paused/stop state, only present once it's been started).
- `Cloud Architecture/` — vendor-agnostic cloud IAM privilege-escalation
  graph engine: parses IAM policy JSON into a common node/edge schema
  (`privesc_graph/schema.py`) and finds escalation paths (e.g. `iam:PassRole`
  + a compute-create action chaining into an overprivileged execution role).
  AWS-only for now (`privesc_graph/parsers/aws.py`) — Azure/GCP parsers,
  live SDK/LocalStack calls, and any agent/skill wiring are explicitly
  future work, not implemented here. Pure JSON in/out, stdlib-only Python,
  no credentials involved anywhere. Run `graph_cli.py demo` for a zero-setup
  worked example; see `Cloud Architecture/README.md` for the CLI and
  `DESIGN.md` for schema/taxonomy rationale and known limitations. Private
  by default like every other folder here — un-ignore explicitly when ready
  to share. This is a defender/architect-side skill demonstration, distinct
  from the offense-only pipeline described above.
- `OffSec Labs/` — one note per paid third-party course lab/module (OSAI+
  so far), named `<Course> - <Module Name>.md`, same
  Recon → Vulnerability → Exploitation → Lessons Learned shape as an HTB
  writeup plus the Skills Required/Skills Learned front matter. No
  dedicated pipeline/agent — worked ad hoc per module. Never public, no
  retired-content carve-out like HTB gets (see "Publishing rule"): the
  whole folder is git-ignored unconditionally. Any script built for a
  module that's reusable beyond that one session (a payload generator, a
  helper) goes in `OffSec Labs/scripts/`, named to match its module
  (`<module-slug>.py`), with a short header docstring (what it builds,
  which target/lab, how to rerun, what to edit to adapt it) since it'll be
  read cold in a future session with none of this session's context —
  linked back to from the module note's Exploitation section, not left
  orphaned. This mirrors the general job-cleanup rule below, applied to
  this specific folder.

## Autonomous agent pipeline
Six subagents live in `.claude/agents/`: `connect-agent`, `recon-agent`,
`exploit-agent`, `privesc-agent`, `writeup-agent` — one per phase of a
box. Each reads its predecessor's notes from `Recon Output/Machines/<target>-*.md`
and writes its own findings there; `writeup-agent` is the one that
produces the final `HTB Writeups/Machines/<target>.md`. `connect-agent` runs first
and resolves a bare target name into something actually reachable: it
spawns HTB machines and confirms the VPN tunnel is up via the HTB API
(`Tooling and Scripts/htb_connect.py`, wrapping `pyhackthebox` — needs
`HTB_API_TOKEN` set in the environment, see that script's docstring), or
resolves an OverTheWire `<wargame><level>` target to its fixed SSH
host/port via `Lab Environment/OverTheWire-Connections.md`. As of
2026-07-17 the `openvpn` and `nmap` binaries carry `cap_net_admin`/
`cap_net_raw` (via `setcap`), so connect-agent starts the OpenVPN tunnel
itself with no `sudo` needed; it still never submits flags to HTB (a
deliberate manual, opt-in action). As of 2026-07-22, `tcpdump`, `arping`,
and `nping` also carry `cap_net_raw`/`cap_net_admin` (`dumpcap` already
had this by default), and `ligolo-ng` (`ligolo-proxy`/`ligolo-agent`) is
installed via apt for pivoting from a foothold — `ligolo-proxy` also
carries `cap_net_admin`, so TUN-interface creation on the attacker side
needs no `sudo`.
Deliberately *not* done: granting capabilities to the `python3` interpreter
itself (would need for e.g. Responder/impacket's raw-socket tools to run
setcap-free) — that would extend those capabilities to every Python
script on the box, not just the intended security tools, judged too broad
a grant for the convenience gained. A sixth subagent, `goal-relay-agent`, turns a finished goal into
a mobile-readable hosted report (via the `Artifact` tool) for checking
progress away from the terminal.

Three skills sit on top, forming a goal stack (Goal → Goal Relay →
Orchestration / Infinite Worker):

- **`pwn-box`** (`.claude/skills/pwn-box/`) — one **Goal**: runs a single
  target through all five subagents in sequence, fully autonomously, and
  owns that goal's entry in `Orchestration/registry.json`. Say "pwn
  <target>" or invoke `/pwn-box <target>`. As of 2026-07-23: HTB/lab
  targets are exploitable by design, so "exploit-agent/privesc-agent found
  no viable vector" is no longer treated as a stop condition on its own —
  `pwn-box` automatically re-runs recon-agent (escalated to full model)
  targeted at that stage's own reported gaps and retries it. This loop is
  uncapped — it keeps going for as many passes as it takes, not a fixed
  budget (see `pwn-box`'s "Handling a Blocked Stage" section). Real hard
  stops (VPN/connect failure, scope ambiguity, an actual session/resource
  ceiling like a usage-limit cutoff) still end the goal immediately. Goal
  Relay always still runs so a blocked run still produces a report.
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

## Sherlocks pipeline (2026-07-24)
Sherlocks are HTB's DFIR/forensics content — an evidence archive plus a
fixed list of text-answer questions about an incident, no shell/root
involved. Structurally nothing like a machine (no recon/foothold/privesc/
root phases), so this is a single subagent, not a chain, and it isn't
wired into `pwn-box`/`orchestrate-goals`/`infinite-worker` — invoke it
directly per Sherlock.

- **`sherlock-agent`** — pulls a Sherlock's scenario/task list via
  `Tooling and Scripts/htb_sherlock.py` (a sibling CLI to
  `htb_connect.py`; same `HTB_API_TOKEN`/venv setup, but talks to
  undocumented Sherlock-specific endpoints found by live-probing the API
  directly, since `pyhackthebox` has no Sherlock support at all), works
  the tasks in order against the evidence, and writes findings to
  `Recon Output/Sherlocks/<name>-sherlock.md`. Drafts the final
  `HTB Writeups/Sherlocks/<name>.md` only when asked, once every task is answered.
  Never submits answers to HTB — same manual/opt-in boundary as machine
  flag submission.
  **Known gap:** the evidence archive can't be downloaded via the API —
  `GET sherlocks/<id>/download` 500s even with a valid token (see the
  script's docstring for the full investigation). Evidence has to be
  downloaded by hand from the Sherlock's page
  (`https://app.hackthebox.com/sherlocks/<id>`) and extracted (zip
  password `hacktheblue`) into `Recon Output/Sherlocks/<name>-evidence/`
  before the agent can start analysis.

## Bug bounty pipeline (2026-07-23, HackerOne first)
A separate, deliberately more conservative track from the HTB pipeline
above — bug bounty targets are real production systems, not disposable lab
boxes, so the posture is prove-then-stop, not get-a-flag. Three new
subagents in `.claude/agents/`:

- **`scope-agent`** — the hard gate. Reads a program's
  `Bug Bounty - <Program>/scope.md`, cross-checks it against the program's
  live platform page, and writes `scope-resolved.md` — the actual
  authorization boundary every other bounty agent must read before acting.
  No `scope-resolved.md`, no work, full stop.
- **`bounty-exploit-agent`** — not `exploit-agent`. Minimal, non-destructive
  proof of concept only: demonstrate impact and stop, never full
  exploitation, never real user data, dry-run before anything with side
  effects, program rate limits/rules from `scope-resolved.md` are followed
  literally. Writes `Bug Bounty - <Program>/Findings/<slug>.md`.
- **`bounty-report-agent`** — drafts a HackerOne-format report from a
  finding into `Bug Bounty - <Program>/Reports/<slug>-draft.md`. Never
  submits — submission is a deliberate manual, opt-in action, same as this
  vault's HTB flag-submission boundary.

Deliberately *not* built yet: a bounty-specific recon agent. Org-wide asset
discovery (subdomain enum, ASN lookups) is different tooling from
`recon-agent`'s single-target nmap-first approach, but for now `recon-agent`
gets reused directly against `scope-resolved.md`'s allow-list with tighter
rate limits as a stopgap rather than building a fork before it's actually
needed. No orchestration skill (a bounty equivalent of `pwn-box`) exists
yet either — each stage is invoked individually with a human checkpoint in
between, on purpose, until the scope-gate and conservative-exploit-posture
pieces have some track record.

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
- A background job's `$CLAUDE_JOB_DIR/tmp` is ephemeral — cleaned up when
  the job is deleted. Any script written there that's reusable beyond the
  immediate task (a payload generator, an exploit helper, anything worth
  reaching for again) must get copied into a durable, findable spot in the
  vault before the session ends — not left for me to dig out of a job
  directory later. Default target: the folder the task's notes already
  live in (e.g. `OffSec Labs/scripts/`, `Tooling and Scripts/`), named
  descriptively, with a short header comment (what it does, how to rerun
  it, what to edit to adapt it) since it'll be read cold with none of the
  session's context — and link to it from whatever note documents the
  task, don't leave it orphaned. One-off debug/investigation scratch (a
  trace dump, a throwaway offset check) can stay in job tmp; the bar is
  "would I want to reach for this again," not "did I write a .py file."

## Boundaries
- HTB/THM/lab targets: full exploitation help, including writing working
  exploit code for these environments, is fair game.
- Bug bounty programs (see "Bug bounty pipeline"): in scope only once a
  program has its own `Bug Bounty - <Program>/scope.md` and
  `scope-agent` has produced a current `scope-resolved.md` from it. Even
  then, the posture is minimal proof-of-concept, not full exploitation —
  see `bounty-exploit-agent`.
- Anything outside that (real, non-lab, non-authorized, or unscoped bounty
  targets) — flag it and ask rather than assuming scope.

## Publishing rule (public GitHub repo)
- Only draft/commit HTB writeups for RETIRED machines (and, by the same
  rule, retired Sherlocks/Fortresses/Challenges). `.gitignore` holds back
  all of `HTB Writeups/*` by default, per content-type subfolder — once a
  specific box is confirmed retired, add an explicit
  `!HTB Writeups/Machines/<target>.md` line (or the matching
  `Sherlocks/`/`Fortresses/`/`Challenges/` path) to `.gitignore` to
  un-ignore just that one file, then commit it.
- Never commit files matching secrets, API keys, `.ovpn` configs, or client
  scope docs — these belong in the private local vault only, per
  `.gitignore`.
