# Interacting with a Long-Lived Reverse Shell via a Named FIFO

Operational technique for this vault's own agent pipeline (foothold-agent /
privesc-agent), not a target-side security finding — worth keeping as a
reusable note since it'll recur on any box where a raw `bash -i` reverse
shell needs to stay alive and be driven across multiple tool calls/agent
handoffs without a real PTY/tmux session available.

## Pattern

```bash
mkfifo /path/to/scratchpad/<target>/fifo
tail -f /path/to/scratchpad/<target>/fifo | nc -lvnp <port> > /path/to/scratchpad/<target>/nc.log &
```
Send a command: `echo '<cmd>' > /path/to/scratchpad/<target>/fifo`, then
read `nc.log` after a couple seconds for output.

## The anti-pattern to avoid: a persistent "holder" process on the FIFO

It's tempting to keep the FIFO's write end open between commands with a
background holder (e.g. `exec 3>fifo; sleep 999999`), reasoning that this
avoids `tail -f` seeing repeated EOFs as different writers open/close the
pipe. **This breaks delivery instead of helping it**: once a long-lived
process holds the FIFO open for writing, `tail -f` stops flushing newly
written data through to its output pipe, even though the bytes are
genuinely sitting in the kernel pipe buffer (confirmed by killing the
holder process — the "missing" output flushes through immediately on kill).
The channel looks completely dead (writes produce no visible output) with
no error anywhere to explain why.

## Fix

Don't use a persistent holder at all. Plain sequential
`echo '<cmd>' > fifo` — each one opening, writing, and closing the FIFO on
its own — works reliably with `tail -f` picking up each write
individually. No holder process needed; a writer only needs to be open for
the instant it's writing.

## A second, unrelated failure mode: reading the FIFO's output side with `cat`

Reading the *output* log with `cat`/`batcat` (rather than `tail -f`) can
also silently kill the channel — `cat` hits EOF and exits the instant the
single writer process on the other end closes its file descriptor between
commands, which looks like "the channel is dead" (no error, just nothing
further) rather than "the reader stopped." Always use `tail -f` on both the
write side (feeding the FIFO into `nc`) and, if piping the log output
anywhere, the read side too — never `cat` a file that's still being
actively appended to by a process that opens/closes its fd repeatedly.

## A third failure mode: a stale leftover `nc`/`tail -f` pair from a prior run

Re-establishing a channel after killing and relaunching the exploit can
silently fail to receive anything even though the new listener appears to
bind correctly, if an **old** `nc -lvnp <port>` (or its paired `tail -f`)
from a previous session/run is still alive in the background — depending on
OS socket reuse behavior, the new listener can look bound while the old
process is actually the one still holding the port. Always `ps -ef | grep
-E "nc |tail -f"` and kill every leftover process explicitly before
launching a fresh listener/FIFO pair, rather than assuming a prior run's
processes died with their originating shell.

## Seen on
- [[connected]] — inherited a non-responsive FIFO channel from the
  foothold hand-off (a "keep the write end open" holder process was in
  use). Root-caused via isolated testing rather than assumption, rebuilt
  the channel without a holder, and it stayed reliable for the rest of the
  privesc chain.
- [[nimbus#Privesc|nimbus]] — used as the sole shell channel into the
  `worker` container across nine separate privesc sessions and a final
  root-achieving one, spanning multiple respawns/re-exploitation cycles.
  Each session verified the channel was still alive with a fresh
  timestamped `echo`/`date` round-trip before reuse, rather than assuming
  a shell left open in a prior session (possibly hours earlier) was still
  responsive — cheap enough to do every time and avoided ever debugging a
  stale-vs-broken-channel ambiguity mid-session.
- [[Helix#Privesc|Helix]] — hit both the `cat`-vs-`tail -f` read-side
  failure and the stale-leftover-process failure across its four sessions,
  each time initially looking like a dead/broken channel with no error
  message anywhere to point at the real cause.
