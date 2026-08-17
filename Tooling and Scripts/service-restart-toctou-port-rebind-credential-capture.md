# Racing a Service Restart to Capture a Privileged Client's Reconnect Handshake

A TOCTOU pattern distinct from classic file-based TOCTOU races: if a
periodic job (cron/systemd timer) restarts a server process and then a
*separate*, privileged client process that depends on it, there's a real
window — however short — between the server process dying and rebinding its
port where nothing is listening. Whatever binds that port first during the
gap receives the reconnecting client's own handshake, including any
credentials the client presents as itself.

## Preconditions

- A periodic restart of a server component immediately followed by a
  restart (or reconnect) of a client component that depends on it — found
  via reading the restart script's actual behavior (see
  [[proc-cmdline-world-readable-behavior-inference]] if the script itself
  isn't readable), not assumed.
- The client component runs as a higher-privilege user than your current
  foothold, and its authentication handshake is worth capturing (username/
  password, client cert, etc.).
- No firewall/network-namespace boundary preventing your foothold from
  binding the same local port during the gap.

## Making the race winnable

The real bottleneck is usually **server-object construction cost**, not the
bind call itself. A naive "rebuild everything, then try to bind" retry loop
can be orders of magnitude too slow for a sub-100ms window. Structure the
race script as:

1. Build the expensive, one-time server object **once**, before the target
   restart event.
2. Tight-loop only the cheap part — `server.start()` /
   `server.stop()` (or `bind()`/`close()` at the socket level) — retrying
   as fast as possible until the bind succeeds.
3. Time the launch against the target's actual next-trigger timestamp
   (`systemctl list-timers <unit>` for a systemd timer) with margin on both
   sides, not a blind long-running loop.
4. On successful bind, log every credential/certificate field presented
   during the client's handshake and hold the port open only long enough
   to catch one connection attempt (the client will typically retry every
   few seconds if the real server doesn't come back, giving multiple
   capture attempts per race window if the first one is missed).

Measure your retry loop's real attempts/second in isolation against an
already-bound port before relying on it — a one-time object-build cost
folded into every retry attempt can be the difference between winning and
never getting close.

## This technique proves a negative just as usefully as a positive

Winning the race and observing an **anonymous** or empty-credential
handshake is a hard, direct disproof that the client holds/transmits a
particular credential — stronger evidence than any filesystem search or
inference from missing file permissions, because it's the client's own
real wire traffic, not a guess.

## Cleanup

The race necessarily makes the real server briefly fail to rebind its own
port. `systemd`'s `Restart=always`/`RestartSec` self-heals this
automatically in most cases — confirm full recovery (`systemctl status`,
re-test the service's actual function) before ending the session, and make
sure no leftover instance of your race script is still holding the port
after the intended window closes.

## Seen on
[[Helix#Rabbit Holes|Helix]] — `helix-cleanup.sh` restarts `helix-plc`
(OPC-UA server) and then `helix-safety` (OPC-UA client, running as root)
~83ms apart, every 5 minutes. Built a fake OPC-UA server (`asyncua`-based,
custom `UserManager.get_user()` override, ~249 bind-attempts/second after
switching to the build-once/retry-cheap-part structure) and won the race
three times, definitively proving `helix-safety` authenticates to the OPC-UA
server anonymously (no username/password/certificate ever presented) —
closing what had looked like the most promising remaining credential lead
on that box.
