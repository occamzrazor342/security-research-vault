# Reading an Unreadable Root Script's Behavior via `/proc/*/cmdline` Polling

On a hardened box you'll often have `Permission denied` on a root-owned
script (`-rwxr-x--- root root`) and on its `journalctl` logs, with no way to
read what it actually does — but on Linux, `/proc/<pid>/cmdline` and
`/proc/<pid>/status` are **world-readable by default regardless of process
owner**, distinct from `/proc/<pid>/cwd`, `/proc/<pid>/exe`, and
`/proc/<pid>/maps`, which respect `ptrace_scope` and normally deny access
across users (`cat /proc/sys/kernel/yama/ptrace_scope` — `1` is the common
hardened default). This asymmetry means you can catch a script's real,
literal command-by-command execution as it runs, without ever having file
permission on it.

## Method

1. Confirm the split empirically first: `readlink /proc/1/cwd` should fail
   (`Permission denied` for another user's process) while
   `cat /proc/1/cmdline` succeeds — this confirms the technique will work
   on this specific box before relying on it.
2. Get the target's exact next trigger time if it's timer/cron-driven
   (`systemctl list-timers <unit> --no-pager`).
3. Run a tight poller (10-20ms resolution) reading `/proc/*/cmdline` for
   every PID, filtering to new/changed entries, logging `(timestamp, pid,
   cmdline, PPid, Uid)` from `/proc/<pid>/status` alongside it to see the
   full parent/child chain and confirm each spawned process's actual
   privilege level.
4. Start the poller with margin before the expected trigger and let it run
   through the full event — short-lived child processes (a few
   milliseconds) will still show up if the poll interval is tight enough
   relative to how long each process lives.

## Why this beats guessing from static permissions alone

Confirming file size (`stat -c "%s"`) against the number/shape of commands
observed is a cheap sanity check that the capture was complete, not
truncated by a slow poll interval missing an early command.

## Seen on
[[Helix#Privesc|Helix]] — `helix-cleanup.sh` (`-rwxr-x--- root root`, 107
bytes, unreadable to the foothold user and `journalctl` also denied)
was fully characterized this way, live during a real systemd-timer trigger,
as three `systemctl restart` invocations against the box's three custom OT
services — confirmed a harmless self-healing job, not a privesc vector,
without ever gaining read access to the script itself.
