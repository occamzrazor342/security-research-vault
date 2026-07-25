# Bridging Two Limited Footholds via a Shared Bind Mount

A pattern worth actively looking for once two separate accounts/footholds
exist on the same box (a container shell plus a real OS-user login, two
different containers, etc.): neither one alone may be enough to reach
root, but if they share a filesystem path — a bind mount, a bind-mounted
volume, an NFS export — each can be enough to supply the *other's* missing
piece.

## The shape

- **Foothold A** has filesystem write access to a directory a privileged
  process will later read from/execute against, but lacks the privilege
  (no sudo, no relevant tooling installed, wrong account) to actually
  trigger that privileged process.
- **Foothold B** has the privilege to trigger the privileged process (a
  sudo rule, a cron job it can influence timing of, a service it can
  restart) but cannot write to the directory that process reads from —
  wrong group ownership, wrong filesystem namespace, wrong container.
- The two compose: stage the payload from A, trigger it from B.

This is easy to miss because each foothold's own enumeration correctly
concludes "no local privesc path from here" — the gap only becomes visible
once both footholds' `/proc/mounts` (or equivalent) are compared and a
shared underlying device/bind-mount target is spotted.

## What to check once you have two footholds

- `/proc/mounts`/`mount` from **both** contexts — same device, same bind
  source path (even if mounted at different paths/subpaths in each), is
  the tell. A device like `/dev/sda4` bind-mounted into a container at one
  path and available directly (or via a different bind mount) to a host
  user at another is exactly this pattern.
- Ownership/group of the specific subdirectory a privileged
  script/service actually reads from — not just the mount point's own
  permissions, which can look more restrictive than a writable
  subdirectory underneath it actually is.
- Whether the tooling needed to build a valid malicious payload (a
  matching library version to guarantee serialization-format
  compatibility, e.g. building a `torch.save()` pickle with the *real*
  installed PyTorch rather than hand-rolling pickle opcodes) exists on
  whichever foothold has the privilege to trigger the load, even if that
  foothold can't write the result to the target directory directly —
  bridge the file across with whatever channel exists between the two
  (base64 over an existing SSH/FIFO/shell channel is usually enough; no
  shared network path or direct file-copy mechanism is required).

## Seen on

- [[bedside#Privesc|bedside]] — `/datastore/checkpoints` (writable by the
  `datawrangler` container foothold, no `sudo`/no `torch` installed there)
  and a narrowly-scoped `sudo` rule for `developer` (real SSH host user,
  has `torch` installed, but not in the group that owns
  `/datastore/checkpoints`) were bridged by building the malicious
  `torch.save()` payload as `developer` (for real pickle-format
  compatibility) and staging it into the shared bind mount from
  `datawrangler` via base64 over existing channels. See
  [[insecure-ml-pickle-deserialization]] for the deserialization mechanism
  itself.
