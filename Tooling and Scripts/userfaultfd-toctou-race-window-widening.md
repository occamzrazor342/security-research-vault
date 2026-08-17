# `userfaultfd`-Widened TOCTOU Races (Turning a Coin-Flip Race Into a Sure Thing)

## The problem it solves

A classic local-privesc TOCTOU bug — a privileged process (kernel code
path, a SUID helper, a root-run script) that checks something (a
permission, a path, a symlink target) and then, in a separate step, acts
on it — is normally exploited by just firing the "check" trigger and the
"swap the thing out from under it" step in a tight loop from parallel
threads/processes and hoping enough iterations land inside the real
window. For a window measured in microseconds (or, per Project Zero's
2022 writeup below, ~12 CPU instructions), pure loop-spam can be
astronomically unreliable or practically impossible — the race isn't
"unwinnable," it's just too narrow for naive parallelism to hit by chance.

## The technique: use a page fault as a synchronization primitive

If the vulnerable code path, at any point during its check-then-act
window, touches memory the attacker controls (a `copy_from_user`-style
read of a buffer that lives in attacker-mmap'd memory, an argument struct,
etc.), register that memory region with `userfaultfd()` before triggering
the operation. The instant the privileged code touches that page, the
kernel suspends the faulting thread and hands control to your userfaultfd
handler thread *before* the access completes — turning a probabilistic
race into a **deterministic pause**: you now have unbounded time to
perform the actual attacker-side move (swap a symlink, rewrite a file,
flip a flag) while the victim is frozen mid-operation, then resolve the
fault (`UFFDIO_COPY`/`UFFDIO_CONTINUE`) to let it proceed into the
now-altered state. This also gives you a clean read/write-fault
distinction (write-protect the page to trap only writes) for pinpointing
exactly which access in the window is the one worth racing against.

Project Zero's 2022 follow-up (`__fget_files()`, ~12-instruction window)
shows a second widening trick worth knowing even when userfaultfd doesn't
apply directly (e.g. the window is pure CPU-time, not a page fault):
replace thread-vs-thread racing with **thread-vs-hardware-timer** racing —
arm a `timerfd`-driven interrupt and deliberately bloat the interrupt
handler's own work (e.g. forcing it to walk a long waitqueue) to
artificially stretch the window from the *interrupt* side rather than the
racing-thread side, plus cache-evicting the target data structure
(`close(dup(fd))` from another core) to add deterministic extra latency
right as the window opens.

## How to apply this on an engagement

1. Confirm it's actually a TOCTOU/race bug, not a straightforward missing
   check — you need a real "check happens, then later, separately, action
   happens" structure (a script that `stat()`s a path then `open()`s it
   later; a setuid binary that validates an argument then re-reads it from
   a buffer; a kernel path with a documented "look up, then dereference
   again" pattern).
2. Identify whether any part of that window touches attacker-supplied
   memory (not just attacker-supplied *arguments* passed by value, but an
   actual buffer/struct read from memory you control the pages of) — if
   so, `userfaultfd` on that page is your synchronization primitive rather
   than a loop-and-pray approach.
3. If the race is filesystem-based rather than memory-fault-based (the
   victim `stat()`s/`open()`s/`read()`s a path, with no memory-fault point
   to hook), the well-known sibling technique is a custom **FUSE**
   filesystem: implement the file the victim will access yourself, and
   simply delay your `getattr()`/`read()` FUSE callback's response for as
   long as you need — this pins the victim mid-syscall with the same
   effect as userfaultfd, without needing a fault-eligible memory buffer
   at all. Worth defaulting to FUSE first for path-based TOCTOU (SUID
   scripts, backup/tar-extraction races, log-rotation races) since it needs
   no kernel-internals knowledge, just a slow filesystem.
4. Only reach for the hardware-timer/cache-eviction approach (Project
   Zero's 2022 post) when neither a memory fault nor a filesystem hook is
   available and the window is a pure CPU-time race — this is
   meaningfully harder to pull off and is closer to kernel-exploit
   territory than a typical engagement needs.

## Source

Google Project Zero, "Racing against the clock — hitting a tiny kernel
race window" (2022) —
https://projectzero.google/2022/03/racing-against-clock-hitting-tiny.html
and "Exploiting race conditions with `userfaultfd`" background referenced
from the same research line —
https://projectzero.google/2016/03/race-you-to-kernel.html

Not yet encountered on a vault box — added from Project Zero research
ahead of hitting it live. Complements [[single-packet-attack-race-condition-timing]]
(that note solves the *remote network-timing* half of winning a race;
this one solves the *local, syscall-level* half — a full remote-to-local
race chain may eventually need both).
