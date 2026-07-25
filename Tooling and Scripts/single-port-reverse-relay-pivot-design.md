# Designing a Single-Port Reverse Relay Pivot (and When Not To)

When a foothold host can reach both the attacker and an otherwise-unroutable
internal target, but you don't yet have (or can't get) a real network-layer
pivot (see [[ligolo-ng-windows-agent-cross-compile]]) — a hand-rolled
app-layer relay is a legitimate fallback. It's also easy to get wrong in
non-obvious ways. This documents five structurally distinct failure modes
hit building one on [[garfield#Privesc|Garfield]], in the order that finding
each one led to the next design.

## Direction: forward relay vs. reverse relay

**Forward relay** (foothold host listens locally, forwards to the internal
target; attacker connects to the foothold host's exposed port) requires the
foothold to accept an inbound connection — which requires either local admin
(to open a firewall exception) or an already-permissive host firewall.
**Don't assume this is available** — a non-admin account on a
default-hardened Windows host cannot open an inbound port, even though the
listener itself starts and looks bound (`Get-NetTCPConnection` shows it
locally; an external port scan finds it closed/filtered — the firewall drops
the packet before the process ever sees it).

**Reverse relay** (foothold host dials *out* to an attacker-controlled
listener) avoids this entirely, since outbound connections are how the
foothold got established in the first place. This is the direction worth
reaching for by default once inbound is ruled out.

## Failure mode 1: pre-dialing both legs eagerly

The naive reverse-relay design pre-opens both the attacker-facing leg and the
internal-target-facing leg immediately, keeping a pool of "ready" pairs for
low-latency handoff. This breaks against any internal target that drops idle
pre-negotiate connections (a hardened SMB server, for instance, that closes a
connection within a couple of seconds if no protocol negotiation starts) —
by the time a pre-dialed leg gets claimed by an actual client, its internal
side is already dead, and it fails immediately and confusingly
(`Bad file descriptor`/`Connection reset by peer`) right when a client shows
up, not when the leg was created.

**Fix:** dial the internal target lazily — connect to the attacker eagerly
(that idle time costs you nothing), but don't dial the internal target until
real traffic (the client's first protocol byte) actually arrives on the
attacker-facing leg.

## Failure mode 2: getting "defer the dial" wrong in .NET/PowerShell

Two ways to get the "defer until first byte" logic wrong, both hit in
sequence:

- A bare `[System.Threading.Tasks.Task]::Run()` call with extra positional
  arguments silently does nothing useful if `Task.Run` has no overload
  matching that call shape — the arguments never bind, and the deferred
  logic never actually runs, with no obvious error.
- A `RunspacePool` + `[powershell]::Create().AddScript().AddArgument()`
  pattern (the standard correct way to hand live .NET objects to background
  PowerShell work) is more correct, but can silently stop replenishing
  worker slots under sustained use for reasons that aren't always worth
  fully root-causing if a simpler design exists.

## The fix that actually held up: one leg, one OS process, no in-process concurrency

Skip in-process threading/pooling primitives entirely. Write one fully
synchronous script: connect to the attacker, block on a first read with a
bounded timeout (so a leg that never gets traffic doesn't wedge forever),
dial the internal target fresh once real data arrives, forward the buffered
first chunk, then bridge bidirectionally until either side closes. Launch
**several independent OS processes** running this same script
(`Start-Process` in a loop) to get the "pool of ready legs" property through
process-level isolation instead of shared in-process state — nothing to get
wedged, because nothing is shared.

**Size the pool for the actual tool's connection behavior, not "one should be
enough."** Tools like `impacket-psexec` open several concurrent SMB
connections per invocation (share access, SVCCTL, and a separate named-pipe
connection for stdout retrieval) — a pool of 3-4 legs produced spurious
`No answer!`/timeout failures that looked like the relay itself was broken;
8-16 legs resolved it. Watch for multiple simultaneous "bridged" log lines
per single tool invocation to confirm this before concluding the relay is
unreliable.

## Other things to check when a relay-based tool looks flaky

- **Tool-specific port constraints.** Some clients hardcode acceptable
  target ports (`impacket-psexec`'s `-port` only accepts `139`/`445`) — the
  relay's client-facing listener has to bind exactly what the tool expects,
  not an arbitrary free port.
- **Connection-rate defenses on the internal target.** A burst of relay
  churn (many connect/disconnect cycles while debugging) can trigger a
  target-side rate limit that resets *every* new connection attempt for a
  cooldown window (~60-90s observed), independent of whether the relay
  itself or any credential is stale. Don't chase a phantom relay bug if
  failures cluster right after a burst and self-clear after a short wait.

## When to stop iterating and build a real pivot instead

A single-port app-layer relay fundamentally can't service any protocol that
needs more than the one forwarded port — most notably anything using the RPC
endpoint mapper (port 135, then a per-boot dynamic high port), like DRSUAPI.
If the next tool you need to run needs a second port, or a dynamically
resolved one, that's the signal to stop iterating on the relay and build a
real network-layer pivot instead — see
[[ligolo-ng-windows-agent-cross-compile]].

## Seen on

- [[garfield#Privesc|Garfield]] — all five iterations above, in this order,
  before landing on the working process-per-leg design; the relay was
  eventually superseded entirely by a real `ligolo-ng` pivot once a
  dynamic-port protocol (DRSUAPI) was needed.
