# Dual-LLM Orchestrator

A hybrid Planner/Execution-Worker harness for pentest engagements and lab
work: **Claude** (via the `anthropic` API) does high-level methodology and
tool-call planning across the full recon → enum/fuzz/analyze → foothold →
privesc → report arc — the same phase shape as the real `pwn-box`
pipeline, just inside one goal-driven loop instead of separate subagents;
a **local
open-weights model** hosted on Runpod (vLLM/Ollama, OpenAI-compatible)
translates each planned action into exact CLI syntax or in-session shell
commands; a local Python middleware substitutes the real target, validates
and runs the command (or sends it into a caught reverse shell), sanitizes
the output, and feeds it back to Claude to continue the loop.

**This is not `pwn-box` and is never invoked by it.** No file here is
referenced by `.claude/skills/pwn-box/` or any agent in `.claude/agents/`
(verified 2026-08-16) — running `main.py` is a manual, standalone action
you take yourself; saying "pwn \<target\>" in a Claude Code session never
reaches this harness, and running this harness never touches
`Orchestration/registry.json` or anything else the real pipeline tracks.
It shares the phase *shape* of `pwn-box` (recon → foothold → privesc) as a
design choice, not because any code is shared. It also has **no
scope-agent equivalent** — `--target` is the only scope boundary; see
Safety model below.

This is infrastructure, not a technique writeup — it's the general-purpose
harness described in the "Custom Orchestration Harness for Pentesting &
Security Labs" project brief (2026-08-16). It's a different thing from
`LLM Training/orchestration/` — that folder is a Claude-independent harness
built around a locally-hosted Qwen2.5-Coder-32B model; this one is a
two-model pipeline with Claude as the strategist.

## Why two LLMs, and why the split is where it is

Claude never sees a real target, credential, or exact CLI flag — it only
emits abstract tool calls (`run_recon(target=TARGET_HOST, scan_type=...)`)
against the schemas in `tool_schemas.py`. The **local worker** never sees
the engagement goal or makes any decision about what to do next — it only
translates one resolved intent into one command string. Splitting it this
way means:

- The (comparatively) expensive, high-quality model spends its tokens on
  strategy, not memorizing `nmap` flag syntax.
- A cheap/local model handles the high-volume, mechanical "what's the exact
  flag for this" step without needing methodology-level reasoning.
- Nothing target-specific — IP, hostname, discovered creds — ever leaves
  this process to reach Anthropic's API.

## Architecture

```
tool_schemas.py    Claude tool-call JSON schemas (abstract TARGET_HOST/TARGET_URL/LISTENER_HOST placeholders)
config.py          Env-driven runtime config: real target, model IDs, safety toggles, session settings
orchestrator.py     The manual agentic loop tying everything together (see below)
local_worker.py     openai-SDK client -> Runpod vLLM/Ollama endpoint; intent -> exact CLI/in-session command
executor.py          Allowlist + shell-metachar validation, then subprocess/Docker exec (LOCAL commands only)
session_manager.py    nc-based reverse-shell listener/catcher for a caught foothold (REMOTE session channel)
sanitizer.py          Strip ANSI, redact secrets, rule-based summarize before it goes back to Claude
service_parser.py     Pure-Python parser for analyze_services (no shell, no local worker call)
notes.py               Writes a markdown run transcript to disk when run() ends, however it ends
main.py               CLI driver: `python main.py --target <ip> --goal "..."`
webui.py               Local GUI driver (Flask): `python webui.py` -> http://127.0.0.1:5000
runpod_guard.py         Standalone Runpod pod auto-stop watchdog (no orchestrator/Anthropic dependency)
```

Ten tools, matching pwn-box's phase shape (recon → enum/fuzz/analyze →
foothold → privesc → report), all defined in `tool_schemas.py`:

| Tool | Local worker involved? | Runs as | Notes |
|---|---|---|---|
| `run_recon` | yes | local subprocess (nmap/rustscan) | |
| `execute_fuzzing` | yes | local subprocess (ffuf/gobuster/wfuzz) | |
| `run_service_enum` | yes | local subprocess (nxc/enum4linux-ng/ldapsearch/rpcclient) | SMB/LDAP/RPC — most HTB/AD boxes need this, not just web |
| `analyze_services` | no | pure Python | parses raw output, no execution |
| `execute_exploit` | yes | local subprocess (delivery) + optional listener | can return a `session_id` |
| `spray_credentials` | yes | local subprocess (nxc) | hard-capped at 30 combos, enforced in code |
| `escalate_privileges` | yes | sent into an existing session | requires a `session_id` |
| `send_to_session` | no | sent into an existing session | Claude writes the command itself |
| `serve_payloads` | no | deterministic (`python3 -m http.server`) | for linpeas.sh/pspy-style scripts — you populate `payloads/` |
| `report_finding` | no | deterministic (records state) | `user_flag`/`root_flag`/`objective_complete` **end the run** |

`orchestrator.py` deliberately uses a **manual** Claude tool-use loop
(`client.messages.create` + a `while` loop), not the Anthropic SDK's beta
`tool_runner` helper — the tool_runner executes tool functions directly,
but every tool call here needs to be intercepted and routed through the
local worker + executor pipeline first, not just called as a plain Python
function. See `python/claude-api/tool-use.md` in the `claude-api` skill for
the manual-loop-vs-tool_runner tradeoff if extending this further.

## Setup

```bash
cd "Tooling and Scripts/dual-llm-orchestrator"
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Now edit .env directly in a text editor and fill in real values —
# NEVER `export` a secret via a `!`/shell command in a Claude Code session:
# that echoes the full command, value included, into the session
# transcript. config.py loads .env automatically at import time (see
# config._load_dotenv) and it's gitignored, so this is the one place a
# real key should ever live.
```

`.env` (see `.env.example` for the template):

```
ANTHROPIC_API_KEY=sk-ant-...
LOCAL_WORKER_BASE_URL=https://<your-runpod-endpoint>/v1
LOCAL_WORKER_MODEL=<model name as loaded on the Runpod pod>
LOCAL_WORKER_API_KEY=not-needed          # only if your Runpod endpoint actually checks it
ATTACKER_IP=10.10.14.5                    # only needed for execute_exploit(reverse_shell=true)
```

Everything else has a sane default — see `config.py` for the full list
(`ANTHROPIC_MODEL`, `REQUIRE_CONFIRMATION`, `USE_DOCKER_ISOLATION`,
`NC_BINARY`, `MAX_CONCURRENT_SESSIONS`, `EXPLOIT_CONNECT_WAIT_S`,
`DEFAULT_SESSION_WAIT_S`, `MAX_PLANNER_ITERATIONS`, `PAYLOADS_DIR`,
`MAX_CREDENTIAL_COMBINATIONS`) — set any of those in `.env` too if you
want to override a default rather than the required connection settings
above. **`MAX_RUN_COST_USD` and `ANTHROPIC_EFFORT` specifically control
spend — read the Cost controls section below before a long run,** not
just this list.

**Run it — CLI:**

```bash
python main.py --target 10.10.10.5 --goal "Get root"
# or, if it's a tracked HTB/lab box -- controls where the run transcript lands:
python main.py --target 10.10.10.5 --target-name cobblestone --goal "Get root"
```

**Run it — GUI:**

```bash
python webui.py
# open http://127.0.0.1:5000
```

A page with target/target-name/goal fields and a Start button, followed
by a live-updating log of planner text, tool calls, findings, and the
final result — same `DualLLMOrchestrator` engine as the CLI, just driven
through `orchestrator.py`'s `on_event` callback (see its `__init__`
docstring) instead of `main.py`'s bare `print()`s. Local-only
(`127.0.0.1`), single run at a time, no auth of its own — it's a
single-operator tool, not a service to expose beyond your own machine.

**Mid-run interjection**: a message box under the Start button, enabled
only while a run is active. Whatever you send there
(`DualLLMOrchestrator.push_interjection()` under the hood, `/interject`
in the GUI) gets folded into the *next* Claude turn as a mid-conversation
`{"role": "system", ...}` message — the same operator-authority channel
the claude-api skill documents for injecting context without invalidating
the cached prefix (see the Cost controls section above). It's not
instant: delivery waits for whatever tool call is currently in flight to
finish, since there's no way to interrupt mid-turn. This is the actual
groundwork for a real chat-style interface (steering a run conversationally
instead of only setting a goal at the start) — the current GUI still
renders it as a one-shot log, not a chat thread, and there's no voice
input yet. Both are the next real iteration on this, not built tonight.

## Cost controls

**Read this before a long run.** The first two real runs against a hard
box (2026-08-16) burned roughly $20 of Anthropic credit in a few hours,
with zero visibility into it happening. The root cause, verified after
the fact from the actual saved transcripts: **no prompt caching.** Every
turn resent the entire accumulated conversation — system prompt, all ten
tool schemas, every prior tool call and result — from scratch, at full
input price, instead of paying the ~1/10th rate for the cached portion.
On a 75-turn run that alone measured out to ~$9.50 in verified input-token
cost; the rest is plausibly Claude Opus 5's extended thinking (on by
default, billed at 5x the input rate), which was never logged either.
Both gaps are fixed now:

- **`cache_control: {"type": "ephemeral"}`** on every Claude call — the
  system prompt + tools cache from turn 1, the growing message history
  caches incrementally each turn after. The single highest-leverage fix;
  this is what actually stops the quadratic-cost-growth pattern.
- **Real-time usage tracking** — every turn logs `[usage] model=... in=...
  out=... cache_read=... turn=$X cumulative=$Y` to stdout, emits a
  `usage` event the GUI renders live in the header cost badge, and the
  final cumulative figure gets written into the run transcript. This is
  an *estimate* at list price from `response.usage` — see
  `orchestrator._track_usage`'s docstring for exactly what it does and
  doesn't account for (it doesn't know your actual negotiated rate, and
  doesn't distinguish 5m vs 1h cache-write TTL).
- **`MAX_RUN_COST_USD`** (default **$5.00**) — a hard, code-enforced
  ceiling checked after every single turn (`orchestrator._run_loop`).
  When cumulative estimated cost crosses it, the run raises and aborts —
  not just logs a warning. This is the actual protection; usage tracking
  alone only gives you visibility *after* the money's spent. Same
  "checked after the turn that crossed it, not before, since you can't
  un-bill a completed request" shape as the Messages API's own session
  budgets — actual spend can exceed this by at most one turn's cost, not
  more. Raise it explicitly per run if a genuinely hard box needs more
  budget than the default covers; don't just bump the default in
  `config.py`.
- **`ANTHROPIC_EFFORT`** (unset by default → API default `"high"`) — a
  direct, legitimate cost lever if you want it: `low`/`medium`/`high`/
  `xhigh`/`max`, nested under `output_config.effort`. Not defaulted down
  automatically since that's a real quality/cost tradeoff you should
  choose, not something this harness silently downgrades for you.
- **`max_tokens` raised from 4096 to 8192** — Claude Opus 5 runs adaptive
  thinking on by default (never disabled here) and thinking + the visible
  response share the same `max_tokens` budget; 4096 risked silent
  truncation mid-tool-call on a heavy-reasoning turn. Not raised further
  without also switching to streaming — the SDK's own non-streaming
  timeout guard trips around the ~16000 mark.

**Separately: the Runpod pod is its own cost stream.** `runpod_guard.py`
closes this — a standalone watchdog, run alongside the pod, that stops it
automatically on whichever fires first: a hard wall-clock ceiling since
the pod's own `createdAt` (`--max-hours`, catches "I forgot about it"),
or sustained low GPU utilization over SSH (`--idle-minutes`, catches "the
run finished and nobody noticed"). Idle detection fails safe — an SSH
query that can't connect is treated as *not* idle, never as a reason to
stop a pod that might just be between tool calls. `runpodctl pod update`
has no auto-stop flag for an already-running pod (only `pod create
--stop-after` does, at creation time, which doesn't help a *resumed*
pod), so this has to be a real poller, not a one-shot flag:

```bash
python runpod_guard.py --pod-id <id> --max-hours 4
python runpod_guard.py --pod-id <id> --max-hours 6 --idle-minutes 20 \
  --ssh-host <ip> --ssh-port <port> --ssh-key ~/.runpod/ssh/runpodctl-ssh-key
```

Run it detached (tmux/nohup), same as vLLM itself needs to be — this
process dying doesn't stop the pod, it just stops watching it. It only
ever calls `runpodctl pod stop`, never `terminate`/`delete`.

## Safety model

This executes real shell commands based on output from two LLMs chained
together — treat that chain as untrusted input, not as a trusted plan. As
of the exploit/privesc extension, there are now **two different trust
boundaries** in play, and they get different controls:

**Tools that run a LOCAL subprocess** (`run_recon`, `execute_fuzzing`,
`run_service_enum`, `execute_exploit`'s delivery step, `spray_credentials`)
— commands run on *your* machine:

- **Binary allowlist** (`executor.ALLOWED_BINARIES`) — each tool may only
  invoke a small, fixed set of known binaries (`nmap`/`rustscan` for
  recon, `ffuf`/`gobuster`/`wfuzz` for fuzzing, `nxc`/`enum4linux-ng`/
  `smbclient`/`ldapsearch`/`rpcclient` for service enum, `python3`/`curl`/
  `searchsploit`/`msfconsole`/`nc` for exploit delivery, `nxc` for credential
  spraying). Anything else the local worker returns is rejected before it
  reaches `subprocess`/Docker.
- **`spray_credentials` has an extra, code-enforced cap**: usernames ×
  passwords over `MAX_CREDENTIAL_COMBINATIONS` (default 30) is rejected in
  `orchestrator._run_spray_credentials` *before* the local worker or
  executor ever sees the request — not just prompted, actually checked in
  code. Matches this vault's standing credential-spray policy: small,
  evidence-based guess sets, never a wordlist brute-force.
- **No shell strings, ever** — commands run with `shell=False` via
  `shlex.split`'d argv. If the local worker's output still contains shell
  metacharacters (`; | & \` $() > <`) after that, it's rejected outright
  rather than "cleaned up" — that's the primary injection vector for a
  hallucinated or manipulated command doing something the tool schema
  never asked for.
- **Docker isolation** (`USE_DOCKER_ISOLATION=1`) — recommended for
  anything beyond a disposable lab VM you don't mind trashing. Runs the
  validated argv inside `docker run --rm --network <DOCKER_NETWORK>
  <DOCKER_ISOLATION_IMAGE> <argv>`. `DOCKER_NETWORK` defaults to `host`,
  which is usually what you want for an HTB/lab target reachable only
  through a VPN interface already up on the attacking host.

**Tools that send into an already-open REMOTE session**
(`escalate_privileges`, `send_to_session`) — commands run on the *target*,
inside the shell a prior `execute_exploit` caught:

- **No binary allowlist, and shell metacharacters are expected and
  allowed.** Once you're inside a caught shell, pipes/redirects/chaining
  are ordinary usage (`find / -perm -4000 2>/dev/null`), not an injection
  vector into *this* process — the blast radius is bounded by what that
  shell can already do on the target, which is inherent to having a
  foothold at all. Trying to allowlist that would just break privesc
  enumeration for no real safety gain.
- **Confirmation is the only gate here** — see below. There is no
  allowlist fallback for these two tools, by design.

**`serve_payloads` and `report_finding` are deterministic Python, not
model-generated** — no local worker, no allowlist, no injection surface in
the usual sense. `serve_payloads` just starts/stops a
`python3 -m http.server` over a directory you populated yourself;
`report_finding` just records state. Both still go through the same
confirmation gate below for `serve_payloads` (it exposes a port on the
network); `report_finding` doesn't need one — recording a finding has no
side effects to gate.

**Applies to every tool that touches the network or a shell:**

- **Confirmation-by-default** (`REQUIRE_CONFIRMATION=1`) — every generated
  command or session-send is printed and requires an interactive `y`
  before it runs. This matters more now than it did for the recon-only
  version: `escalate_privileges`/`send_to_session` have no allowlist
  behind them, so confirmation is the *only* backstop for those two. Turn
  it off only for a run you've already scoped and are prepared to babysit;
  see this vault's `Tooling and Scripts/Agent Operating Principles.md` for
  the general stance on autonomous execution boundaries.
- **No RoE/scope-parsing exists, on purpose (as of 2026-08-16).** `--target`
  is the only scope boundary this harness has. It does not read, parse, or
  enforce against a rules-of-engagement doc — if you pass it OffSec RoE
  text as part of `--goal`, Claude will *read* it as context, but nothing
  gates the tool calls against it, unlike the bug-bounty pipeline's
  `scope-agent`. Now that this harness can run real exploit code and hold
  a live shell on the target, that gap has materially higher stakes than
  it did for recon/fuzzing alone — you are the only scope gate, and that's
  a deliberate choice, not an oversight to fix later.
- **Reverse-shell listeners have no authentication.** `execute_exploit`'s
  `nc -lvnp <port>` treats whatever connects as the session — fine for a
  lab/HTB target reachable only through your own VPN interface; never
  expose the listener port beyond that.

## Session model

`execute_exploit(reverse_shell=true)` starts an `nc -lvnp <port>` listener
*before* firing the exploit delivery command, so the callback isn't missed
by a race between "start listening" and "trigger the payload." Once the
target connects, that `nc` process's own stdin/stdout become the channel —
`escalate_privileges` and `send_to_session` write to its stdin and read
from a queue a background thread fills from its stdout (see
`session_manager.py`'s module docstring for the full mechanics).

What this does and doesn't give you:

- **Yes:** a real, ongoing shell on the target you can send arbitrary
  commands into across multiple tool calls, addressed by `session_id`.
- **No PTY at the module level, but Claude upgrades it automatically.**
  `session_manager.py` itself never allocates a pseudo-terminal — it's a
  dumb pipe. What makes `sudo`/`su`/interactive tools work anyway is
  `orchestrator._SYSTEM_PROMPT` instructing Claude to send
  `python3 -c 'import pty; pty.spawn("/bin/bash")'` via `send_to_session`
  as the very first thing it does once a session shows `connected`, before
  any enumeration. This is prompted behavior, not a code-level guarantee —
  if you're driving `send_to_session`/`escalate_privileges` by hand rather
  than letting Claude run the loop, you need to send that line yourself.
- **Reads are still timing-based, PTY or not.** Write the command, drain
  whatever arrives for `wait_s` seconds, return it as one blob — there's
  no prompt detection. A slow command needs a longer `wait_seconds` on
  that specific `send_to_session` call, not a different tool.
- **No cross-run persistence.** Sessions live only for the duration of one
  `orchestrator.run()` call — `run()` closes every open session in a
  `finally` block on the way out, whether it finished cleanly, hit the
  iteration cap, hit a terminal `report_finding`, or raised. Restarting
  `main.py` means re-establishing the foothold.
- **`ATTACKER_IP` must be an address the target can actually route back
  to** — usually your VPN interface (`tun0` for HTB/lab targets), not
  `127.0.0.1` or a NAT'd address the target can't reach.

## Findings & how a run ends

`report_finding` is the only clean "done" signal in this harness — without
it, the loop just runs until Claude stops calling tools or
`MAX_PLANNER_ITERATIONS` is hit, and you'd be parsing plain text to figure
out whether it actually succeeded.

| `finding_type` | Effect |
|---|---|
| `user_flag` / `root_flag` | Ends the run **immediately** — no more Claude turns, no more tool calls, even if there were more in flight this turn |
| `objective_complete` | Same as above, for goals that aren't literally a flag file (e.g. "confirm the web foothold") |
| `blocked` | Recorded, but the run **keeps going** — a clear marker that Claude's out of ideas right now, not a stop |

The system prompt tells Claude not to declare success in plain text —
`report_finding` with real evidence (the actual command output, not a
plan to get it) is the only path to a terminal state. `orchestrator.run()`
returns `[<finding_type>] <content>\nEvidence: <evidence>` when one fires,
and every finding recorded during the run — terminal or not — is on
`DualLLMOrchestrator.findings` and in the transcript (`main.py` prints
both after the run).

## Run transcripts

Every `run()` call writes a markdown transcript when it's done, however it
ends — see `notes.py`. It contains the goal, every finding, and every tool
call with its exact params and output, following this vault's own
convention of verbatim command/output blocks rather than paraphrases.

- **`--target-name` given** (a tracked HTB/lab box) → written to this
  vault's own `Recon Output/Machines/<target-name>-dual-llm-run-
  <timestamp>.md`, next to `recon-agent`'s own raw notes for that target.
  `Recon Output/` is gitignored by default (see the vault's top-level
  `.gitignore`), so this is private the same way recon-agent's notes are —
  nothing extra to configure.
- **No `--target-name`** (a bare IP, an OffSec lab, anything untracked) →
  written to this folder's own `./runs/` instead, which has its own
  `.gitignore` entry so it never gets swept into the public repo by
  accident.

This is a raw transcript, not a reviewed writeup — verify before treating
anything in it as confirmed. If a run does root a real HTB box, turn the
transcript into a proper writeup via `writeup-agent` once the box retires,
same as any other engagement.

## Output sanitization

`sanitizer.py` is intentionally rule-based, not another LLM call, on the
hot path — it strips ANSI codes, redacts anything that looks like a live
credential (AWS keys, PEM private key blocks, `password=`/`api_key=`
patterns), and if the result is still over `MAX_OUTPUT_CHARS`
(default 6000), keeps the lines that match recon/fuzzing "high signal"
patterns (open ports, HTTP status codes, `CVE-`, error/fail lines) plus a
head/tail sample, and says explicitly how much was dropped. This keeps
Claude's context focused on decisions, not raw terminal noise, without
adding a second model call to every tool result.

## Extending with a new tool

1. Add the schema to `tool_schemas.py` — use an abstract placeholder for
   anything target-specific (add new placeholders to
   `config.OrchestratorConfig.placeholder_map` if needed).
2. Decide which trust boundary it belongs to (see Safety model above):
   - Runs as a **local subprocess** → add its allowed binaries to
     `executor.ALLOWED_BINARIES` and route it through
     `_run_via_local_worker`-style handling in `orchestrator.py` (see
     `run_recon`/`run_service_enum`/`spray_credentials` for the pattern —
     `spray_credentials` also shows how to add a pre-check *before*
     calling the local worker, if your tool needs one).
   - Sends into an **existing remote session** → route it like
     `escalate_privileges`/`send_to_session` — no `ALLOWED_BINARIES` entry,
     no `validate_command()` call.
   - Needs **neither the local worker nor a session** (pure Python, like
     `analyze_services`/`serve_payloads`/`report_finding`) → a plain
     Python function. If it starts a long-lived background process (like
     `serve_payloads`), track its handle as instance state and stop it in
     `_stop_payload_server`-style cleanup, called from `run()`'s `finally`.
3. Register the new handler in `orchestrator._handle_tool_call`'s
   `dispatch` dict, and extend `local_worker._SYSTEM_PROMPT` with
   tool-specific guidance if it goes through the CLI-generation pipeline.

## Known limitations / not built here

- **No retry/backoff around the Runpod endpoint** — a cold pod or a
  network blip surfaces as a plain exception up through `_handle_tool_call`
  (caught and returned to Claude as a tool error, so the loop doesn't
  crash, but it doesn't retry either).
- **PTY upgrade is prompted, not enforced** — see Session model. If
  Claude skips it (or you're driving `send_to_session` manually), nothing
  forces the upgrade; you'll just see `sudo`/interactive commands hang or
  misbehave and have to notice and fix it yourself.
- **No wordlist/wordlist-source management** — `execute_fuzzing`'s local
  worker guidance assumes a couple of hardcoded common paths (dirb's
  `common.txt`, SecLists' `raft-medium-directories.txt`). If those aren't
  installed at those exact paths, or you want a different list, extend
  `local_worker._SYSTEM_PROMPT`'s guidance for that tool.
- `analyze_services`'s regexes are tuned for `nmap`/`ffuf`/`gobuster` output
  shapes specifically — extend `service_parser.py`'s patterns if you add a
  recon tool with a different output format (e.g. `run_service_enum`'s
  `nxc`/`enum4linux-ng` output currently isn't parsed by it at all, only
  read as raw text).
- **`execute_exploit`'s local-delivery allowlist** (`python3`, `curl`,
  `searchsploit`, `msfconsole`, `nc`) and **`run_service_enum`'s allowlist**
  (`nxc`/`crackmapexec`, `enum4linux`/`enum4linux-ng`, `smbclient`,
  `ldapsearch`, `rpcclient`) are starting sets for common patterns, not
  exhaustive — extend them deliberately per `ALLOWED_BINARIES`'s docstring
  in `executor.py` if a technique needs a binary that isn't there. Windows/
  AD-heavy privesc chains (Kerberoasting, DCSync, golden/diamond tickets)
  aren't covered by any dedicated tool here — `escalate_privileges`/
  `send_to_session` can still run `impacket-*` commands manually since
  those aren't allowlist-gated once you're in a session, but there's no
  structured tool for them the way `run_service_enum` structures SMB/LDAP.
- **No multi-session juggling UI** — if a run somehow ends up with more
  than one open session (not a normal flow, since `execute_exploit` is
  usually called once per foothold), there's nothing beyond `session_id`
  string-matching to keep track of which is which; that's on Claude's own
  bookkeeping in its response text, not enforced anywhere.
- **`serve_payloads` doesn't validate file integrity or track what's been
  fetched** — it's a bare `http.server`; if you want to confirm a script
  actually landed intact on the target, that's a `send_to_session` hash
  check (`md5sum <file>`), not something this tool does for you.
