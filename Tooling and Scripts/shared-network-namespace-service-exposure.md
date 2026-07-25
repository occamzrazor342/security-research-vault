# Shared Network Namespace Breaks "Localhost-Only" Isolation Between Containers

`--network=host` (or an equivalent shared network namespace) on a
container means that container's `localhost`/`127.0.0.1` **is** the host's
`localhost` — any service the host binds to loopback, intending it to be
reachable only from processes actually running on the host, is just as
reachable from inside that container. This is a distinct failure mode from
the more commonly checked "loopback-bound service is still attack surface
once you have any foothold" lesson (see the Techniques Index entry on
that) — here the surprising part isn't that loopback binding is a weak
boundary in general, it's that a *container* someone might reasonably
assume is network-isolated from the host turns out not to be, because of
how it was launched.

## How to spot it

- `hostname`/`/etc/hostname` inside a shell reporting a container-looking
  name, but `/proc/1/cgroup` or PID 1 being something other than `init`/
  `systemd` (e.g. an application process directly) — one signal of "this
  is a container," not proof either way about its network mode.
- `/proc/net/tcp`/`/proc/net/tcp6` (hex-encoded local port column) inside
  the container showing ports you *know* belong to other services on the
  host (SSH's 22 = `0016`, HTTP's 50 = `0050`, etc.) — if those show up
  and there's no `ss`/`netstat` binary to check more directly, this is the
  fallback way to confirm shared network namespace from inside a minimal
  container.
- `/etc/hosts` inside the container already containing the box's real
  hostnames/vhosts without anything in the container's own setup
  explaining why.
- A port an external scan reported `filtered`/no-response turning out to
  be answering cleanly the instant it's queried from inside *any* foothold
  on the box, container or not — the "external firewall" was never
  actually gating that port from a process standpoint, only from the
  network path an outside scanner has to take.

## Why it matters operationally

A service bound to loopback specifically *because* the developer assumed
"only processes on this host can reach it" is depending on network
namespace isolation as an implicit trust boundary — reasonable if every
process on the box really does run in the same trust tier, wrong the
moment any lower-privileged container shares that same network namespace.
Once confirmed, treat every loopback-bound service as reachable exactly
like an externally-exposed one for the purposes of continuing
enumeration/exploitation from that foothold — `curl localhost:<port>`
directly, no port-forwarding or pivoting required.

## Seen on

- [[bedside#Foothold|bedside]] — the `datawrangler` foothold container
  runs with a shared (host) network namespace but an isolated filesystem
  and PID namespace. This resolved recon's original "port 3000 filtered
  externally" finding (it's the host's own `esm.sh/x` dev server, bound to
  loopback as the real host user `developer`) and made
  `curl http://localhost:3000/...` from inside the container a direct path
  to [[CVE-2025-59341]], an LFI that read `developer`'s SSH key straight
  off host disk.
