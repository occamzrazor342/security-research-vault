# Docker Container-Escape Enumeration Checklist

Landing root *inside* a container is not host root. Before pivoting away
to look for a completely different vector, run this checklist — it's cheap,
systematic, and each item either finds an escape or rules one out with a
concrete, citable reason (useful for the writeup, not just for yourself).

## 1. Mounts — `mount` / `/proc/self/mountinfo`

- `mount` alone shows the mounted filesystems, but **check the actual
  bind-mount source** via `/proc/self/mountinfo`'s 4th field (the "root of
  the mount within the filesystem"), not just the target path — a bind
  mount can point at a totally different path on the host than its
  in-container mountpoint name suggests.
- `/var/run/docker.sock` mounted in = game over (see
  [[docker-management-api-privesc]] for what that access is worth).
- A bind-mounted subtree that happens to be a subdirectory of the host's
  own root-owned home directory is still just that one subtree — mount
  boundaries are enforced by the VFS mount tree, not by the source path
  string, so `cd ..` from inside it does **not** walk up into the rest of
  the host filesystem. Don't assume "this bind mount's source looks like
  it's under a juicy host path" means the rest of that host path is
  reachable too.
- No raw block device node (`/dev/sda*` etc.) exposed inside the container
  means there's nothing to `mount` fresh even with capabilities, absent
  `CAP_SYS_ADMIN` anyway.

## 2. Capabilities — `/proc/self/status` (`CapEff`) or `capsh --decode`

Decode the effective capability bitmask and compare against Docker's
*default* set (`CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID,
SETPCAP, NET_BIND_SERVICE, NET_RAW, SYS_CHROOT, MKNOD, AUDIT_WRITE,
SETFCAP`). Anything beyond that default set is what to chase:
`CAP_SYS_ADMIN` (mount, plus a long list of other tricks), `CAP_SYS_PTRACE`
(process injection into host-shared PID namespace), `CAP_SYS_MODULE`
(kernel module load), `CAP_DAC_READ_SEARCH` (bypass file read permission
checks). A container running with exactly the default set (or a subset of
it) is not `--privileged` and offers no capability-based escape.

## 3. Namespace sharing — PID, network, user

- **PID namespace**: `ps aux`/`ps auxf` inside the container. If it shows
  only the container's own process tree (not the host's `init`/`systemd`
  and every other host process), `--pid=host` is not in play.
- **Network namespace**: `ip a`/`ss` showing a bridge interface
  (`eth0` on a private `172.x`/`10.x` range with a gateway) means a real
  isolated network namespace — see
  [[shared-network-namespace-service-exposure]] for the opposite case
  (`--network=host`) and how to detect it when `ss`/`netstat` aren't
  available (`/proc/net/tcp` hex-decoded port list).
- **User namespace remap**: `cat /proc/self/uid_map` / `gid_map`. A
  non-identity mapping (host uid range shifted away from 0) means
  container "root" isn't host root even if a write escapes the container's
  filesystem view. An identity mapping (`0 0 4294967295`) means container
  uid 0 genuinely *is* host uid 0 — worth confirming explicitly, since it's
  what turns "a file written via a bind mount" into "a file the host
  actually treats as root-owned."

## 4. Gateway/host port sweep from inside the container

`nc -z -w1 <gateway-ip> <port>` across common admin/DB/message-queue/Docker
API ports. On a minimal image (Alpine/busybox `ash`), bash's `/dev/tcp/...`
pseudo-device does **not** work — it silently fails even against a known-open
port. Use `nc -z` (or `/bin/sh -c '(exec 3<>/dev/tcp/host/port)'` only
under a real bash) as the reliable substitute in a busybox environment. If
`nc`/`nmap`/`arping`/`fping` are *all* absent (a genuinely minimal image),
a hand-rolled parallel ICMP-ping + TCP-connect sweep in pure Python (see
`Tooling and Scripts/exploits/nimbus/bridge_subnet_sweep.py` for a
reusable template) covers the same ground — don't skip the sweep just
because the usual tools aren't installed.

## 5. Filesystem secret sweep

`find / -xdev -iname 'id_rsa*' -o -iname '*.pem' -o -iname 'authorized_keys'`
(the `-xdev` matters — stay within the container's own filesystem, don't
descend into any bind-mounted host subtree redundantly if it's already
being checked separately). Expect false positives from vendored test
fixtures (npm packages that ship known-public test SSH keys under
`node_modules/**/test/fixtures/`) — verify a hit is a real, non-test key
before treating it as a lead.

## When all five come back clean

That's a real, citable conclusion — "this container has none of the usual
escape primitives" — not a dead end to gloss over. Move to whatever
credentials/data *are* reachable from inside the container (app database,
environment variables, config files) and test those for reuse against the
host's other services instead of continuing to hunt for a container-escape
bug that may not exist on this particular box.

**A clean result on this checklist rules out *classic* container escapes
specifically — it doesn't rule out root via a completely different
adjacent service the container can reach** (an unauthenticated backend,
a cloud-service emulator, etc.). See [[nimbus]] below: this exact
checklist came back clean against the `worker` container itself, and the
real path to root turned out to be several hops further out, through a
misconfigured LocalStack backend's own CodeBuild service — a genuinely
different execution primitive from anything this checklist tests directly.

## Seen on

- [[Silentium#Privesc|Silentium]] — ran this exact checklist against the
  Flowise container (root inside, Alpine 3.22.1) and confirmed every item
  clean: bind mount confined to `/root/.flowise` on the host, default-minus-
  `CAP_MKNOD` capability set, non-shared PID/network namespaces, identity
  uid/gid mapping, only the box's own known 22/80 reachable from the
  gateway, no real secrets beyond npm test fixtures. Pivoted instead to an
  environment-variable credential (`SMTP_PASSWORD`) that turned out to be
  reused as a real host SSH password for the account already identified in
  the app's own DB.
- [[nimbus#Privesc|nimbus]] — confirmed every item clean against the
  `worker` container (`CapEff` all-zero, AppArmor `docker-default`
  enforcing, seccomp active, no user-namespace remap, no `docker.sock`,
  read-only cgroupfs, no crontab, no leaked key material). Root ultimately
  came from a misconfigured adjacent LocalStack backend reachable from
  this same container (see
  [[localstack-unauthenticated-backend-bypass]] and
  [[localstack-codebuild-privileged-mode-container-escape]]), not from
  anything this checklist itself would have caught — a genuine example of
  "checklist clean" and "box has no root path" being different
  conclusions.
