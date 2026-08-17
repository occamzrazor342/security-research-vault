# Pinning traffic to the right interface when two VPN tunnels share an overlapping route

## The situation

This vault routinely runs more than one HTB VPN tunnel at once (e.g. a
Machines tunnel on `tun0` alongside a separate Fortress engagement's tunnel
on `tun1`), and HTB's own lab ranges overlap across products — both can
easily claim routes inside the same `10.129.0.0/16` (or `10.10.14.0/23`)
block. Linux only keeps one route per destination prefix; whichever tunnel's
route got installed **first** wins the kernel's routing table, silently, for
every subsequent tool that doesn't explicitly pin its interface. There's
usually no `CAP_NET_ADMIN` available in the working shell to just
`ip route replace` the correct one in (and per this vault's own rules, that's
not a `sudo`-workaround situation to reach for anyway) — so the fix is
per-tool interface pinning, not routing-table surgery.

## Outbound: pin every client tool explicitly

```bash
nmap -e tun0 -Pn -sS -T4 -p- <target>
curl --interface tun0 http://<target>/
ping -I tun0 <target>
```

For raw Python sockets (smuggling probes, hand-rolled protocol clients,
etc.), the equivalent is `SO_BINDTODEVICE` — a per-socket-option syscall,
not a raw-socket capability, so it works fine without `setcap` on the
Python interpreter even in an environment that deliberately doesn't grant
`python3` broad raw-socket capabilities:

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, 25, b"tun0\0")  # SO_BINDTODEVICE
s.connect((target_ip, 80))
```

## Inbound: a plain listener can silently die in `SYN-RECV` forever

Interface pinning for *outbound* requests isn't the whole problem — a
callback/reverse-shell **listener** has the same issue on the reply path,
and it fails in a much more confusing way. A plain `nc -lvnp <port>` has no
way to force which interface it replies out of. If the kernel's routing
table sends return traffic for the target's `/16` out the *wrong* tunnel,
the SYN-ACK goes out with the wrong source IP (the other tunnel's own
assigned address) — the target silently drops it because it doesn't match
the 4-tuple it dialed, and retransmits its SYN forever. The listener just
looks permanently "not yet connected" (`ss` shows `SYN-RECV`, never
`ESTAB`) with zero indication that routing, not the payload/exploit chain,
is the actual problem. This is easy to misdiagnose as "the RCE trigger
didn't fire" when the trigger fired correctly and the shell process is
sitting there waiting on a TCP handshake that will never complete.

**Diagnosis:** `ss -tnp | grep <port>` stuck in `SYN-RECV`, plus a
`tcpdump -i <correct-tun> -n port <port>` capture showing only inbound SYN
retransmits and never an outbound SYN-ACK, confirms this is a routing
problem, not an exploit problem. Cross-check with `ip route` — if the
target's own `/16` only has one route entry and it points at the wrong
tunnel device, that's the cause.

**Fix:** `socat` supports `so-bindtodevice=<iface>` on a `TCP4-LISTEN`,
which pins the listening socket — and, critically, every connection it
accepts and its replies — to a specific interface regardless of what the
routing table says:

```bash
mkfifo /tmp/shell_fifo
nohup bash -c "tail -f /dev/null > /tmp/shell_fifo" &
nohup socat -d -d TCP4-LISTEN:443,reuseaddr,so-bindtodevice=tun0 STDIO \
  < /tmp/shell_fifo > /tmp/shell_output.log 2>/tmp/socat_stderr.log &
ss -tlnp | grep ":443 "
# LISTEN ... 0.0.0.0%tun0:443 ...   <- confirms the pin took effect
```

The `%tun0` in the `ss` output is the confirmation the bind actually applied
— without it, the listener is still exposed to the same routing-table
ambiguity even though it looks correctly configured.

Confirmed working non-root (no `setcap` needed on `socat` itself for this
particular option — it's a standard `SO_BINDTODEVICE` setsockopt call, same
underlying mechanism as the Python case above).

## When to reach for this

Any time more than one VPN tunnel is up simultaneously and both plausibly
route to overlapping lab address space — check `ip route` for the target's
prefix *before* assuming a target is unreachable or a reverse shell "isn't
connecting," and pin both the outbound recon/exploit traffic and any
listener you stand up. Full worked example (including the fifo-based
interactive-shell pattern) from the box this was diagnosed on:
[[Eloquia#Privesc|Eloquia]], `Tooling and Scripts/exploits/eloquia/setup_bindtodevice_listener.sh`.
